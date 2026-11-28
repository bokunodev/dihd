package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/bokunodev/dihd/blocklist"

	"github.com/coocood/freecache"
	"github.com/miekg/dns"
)

type Handler struct {
	ctx       context.Context
	cache     *freecache.Cache
	client    *http.Client
	upstreams upstreams
	blocklist *blocklist.BlockList

	maxTTL int
	minTTL int
	negTTL int

	debug bool
}

type upstreams struct {
	idx  atomic.Uint32
	urls []string
}

func (u *upstreams) next() string {
	if len(u.urls) == 0 {
		return ""
	}

	i := u.idx.Add(1) - 1
	return u.urls[i%uint32(len(u.urls))]
}

func (handler *Handler) ServeDNS(w dns.ResponseWriter, msg *dns.Msg) {
	if len(msg.Question) == 0 {
		_ = w.WriteMsg(msg.SetReply(msg).SetRcodeFormatError(msg))
		return
	}

	if len(msg.Question) > 1 {
		_ = w.WriteMsg(msg.SetReply(msg).SetRcode(msg, dns.RcodeNotImplemented))
		return
	}

	domain := dns.CanonicalName(msg.Question[0].Name)
	if handler.blocklist.Lookup(domain) {
		reply := msg.SetReply(msg).SetRcode(msg, dns.RcodeSuccess)
		question := msg.Question[0]

		switch question.Qtype {
		case dns.TypeA:
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.RcodeSuccess,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IPv4zero,
			})
		case dns.TypeAAAA:
			reply.Answer = append(reply.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.RcodeSuccess,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: net.IPv6zero,
			})
		default:
			reply = reply.SetRcode(msg, dns.RcodeNameError)
		}

		reply.Authoritative = true
		_ = w.WriteMsg(reply)
		return
	}

	key := fmt.Appendf(nil, "%s|%d|%d", domain, msg.Question[0].Qtype, msg.Question[0].Qclass)
	val, err := handler.cache.Get(key)
	if err == nil {
		slog.Debug("cache hit", "key", key)
		reply := &dns.Msg{}
		err = reply.Unpack(val)
		reply = reply.SetReply(msg)
		if err != nil {
			slog.Error("unable to unpack reply from cache", "reason", err)
			replyWithServerFailure(w, msg)
			return
		}

		err = w.WriteMsg(reply)
		if err != nil {
			slog.Error("unable to write dns response", "reason", err)
		}

		return
	}

	// treat cache error as cache miss
	if !errors.Is(err, freecache.ErrNotFound) {
		slog.Error("unable to get cache value", "reason", err)
	}

	slog.Debug("cache miss", "key", key)
	payloadBuf, err := msg.Pack()
	if err != nil {
		slog.Error("unable to pack dns message", "reason", err)
		replyWithServerFailure(w, msg)
		return
	}

	var responseBuf []byte
	var lastErr error
	var upstream string
	// retry 5 times
	for attempt := range 5 {
		upstream = handler.upstreams.next()
		responseBuf, err = doRequest(handler.ctx, handler.client, upstream, payloadBuf, handler.debug)
		if err == nil {
			lastErr = nil
			break
		}

		slog.Warn("DOH query failed", "reason", err, "attempt", attempt, "upstream", upstream)
		lastErr = err
	}

	if lastErr != nil {
		slog.Error("failed to resolve query", "reason", err, "upstream", upstream)
		replyWithServerFailure(w, msg)
		return
	}

	reply := &dns.Msg{}
	err = reply.Unpack(responseBuf)
	reply.SetReply(msg)
	if err != nil {
		slog.Error("unable to unpack dns response from upstream", "reason", err)
		replyWithServerFailure(w, msg)
		return
	}

	replyBuf, err := reply.Pack()
	if err != nil {
		slog.Error("unable to pack dns reply", "reason", err)
		replyWithServerFailure(w, msg)
		return
	}

	ttl := calcTTL(reply, handler.minTTL, handler.maxTTL, handler.negTTL)
	err = handler.cache.Set(key, replyBuf, ttl)
	// keep serving the client at cost of performance
	if err != nil {
		slog.Error("unable to store cache", "reason", err)
	}

	_, err = w.Write(replyBuf)
	if err != nil {
		slog.Error("unable to write dns response", "reason", err)
		return
	}
}

func calcTTL(msg *dns.Msg, minTTL, maxTTL, negTTL int) int {
	if msg == nil {
		return 0
	}
	if msg.Rcode == dns.RcodeServerFailure ||
		msg.Rcode == dns.RcodeFormatError ||
		msg.Rcode == dns.RcodeRefused {
		return 0
	}

	// Negative or empty answer -> short TTL
	if len(msg.Answer) == 0 {
		if negTTL <= 0 {
			return 0
		}

		return negTTL
	}

	ttl := maxTTL
	for _, rr := range msg.Answer {
		if rr == nil {
			continue
		}
		rrTTL := int(rr.Header().Ttl)
		if rrTTL > 0 && rrTTL < ttl {
			ttl = rrTTL
		}
	}

	if ttl < minTTL {
		ttl = minTTL
	}

	if ttl > maxTTL {
		ttl = maxTTL
	}

	return ttl
}

func replyWithServerFailure(w dns.ResponseWriter, msg *dns.Msg) {
	_ = w.WriteMsg(msg.SetReply(msg).SetRcode(msg, dns.RcodeServerFailure))
}

func newDoHClient(bootstrap map[string][]string, timeout time.Duration) *http.Client {
	baseDialer := &net.Dialer{
		Timeout:   1 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return baseDialer.DialContext(ctx, network, addr)
			}

			ips, ok := bootstrap[host]
			if !ok || len(ips) == 0 {
				return baseDialer.DialContext(ctx, network, addr)
			}

			var lastErr error
			for _, ip := range ips {
				target := net.JoinHostPort(ip, port)
				conn, err := baseDialer.DialContext(ctx, network, target)
				if err == nil {
					return conn, nil
				}

				lastErr = err
			}

			return nil, fmt.Errorf("all bootstrap IPs failed for %s: %w", host, lastErr)
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

func doRequest(ctx context.Context, client *http.Client, url string, payload []byte, debug bool) ([]byte, error) {
	method := http.MethodPost

	slog.Debug("request", "method", method, "url", url)

	request, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payload))
	if err != nil {
		slog.Error("unable to construct http request", "reason", err)
		return nil, err
	}

	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")

	response, err := client.Do(request)
	if err != nil {
		slog.Error("unable to perform http request", "reason", err)
		return nil, err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		slog.Warn("upstream error status code", "code", response.StatusCode)
		return nil, fmt.Errorf("status code error: %d", response.StatusCode)
	}

	responseBuf, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		slog.Error("error reading http response body", "reason", err)

		return nil, err
	}

	return responseBuf, nil
}
