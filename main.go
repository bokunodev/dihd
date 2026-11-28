package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"

	"github.com/bokunodev/dihd/blocklist"

	"github.com/coocood/freecache"
	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/miekg/dns"
)

var k *koanf.Koanf

func init() {
	cfgPath := flag.String("config", "", "path to dnsd.toml config file")
	flag.Parse()

	if *cfgPath == "" {
		fmt.Println("missing required argument `config`")
		os.Exit(2) // invalid argument
	}

	k = koanf.New(".")
	if err := k.Load(file.Provider(*cfgPath), toml.Parser()); err != nil {
		panic(err)
	}

	addSrc := false
	level := slog.LevelError
	if k.Bool("debug") {
		addSrc = true
		level = slog.LevelDebug
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: addSrc,
		Level:     level,
	}))

	slog.SetDefault(log)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	bl, err := blocklist.New(k.MustString("server.blocklist"))
	if err != nil {
		slog.Error("unable to load blocklist slab file", "reason", err)
		os.Exit(1)
	}

	handler := &Handler{
		ctx:       ctx,
		cache:     freecache.NewCache(512 * 10000),
		upstreams: upstreams{urls: k.MustStrings("server.upstreams")},
		client:    newDoHClient(k.MustStringsMap("server.bootstrap"), k.MustDuration("server.timeout")),
		blocklist: bl,

		maxTTL: int(k.MustDuration("dns.max_ttl").Seconds()),
		minTTL: int(k.MustDuration("dns.min_ttl").Seconds()),
		negTTL: int(k.MustDuration("dns.neg_ttl").Seconds()),
		debug:  k.Bool("debug"),
	}

	server := dns.Server{
		Addr:      k.MustString("server.address"),
		ReusePort: k.Bool("server.reuse_port"),
		ReuseAddr: k.Bool("server.reuse_addr"),
		Net:       k.MustString("server.network"),
		Handler:   handler,
	}

	wg := sync.WaitGroup{}
	defer wg.Wait()

	wg.Go(func() {
		<-ctx.Done()
		slog.Info("shutting down server")
		err := server.Shutdown()
		if err != nil {
			slog.Error("server shutdown error", "reason", err)
		}
	})

	slog.Info("server listening", "address", k.MustString("server.address"))
	if err := server.ListenAndServe(); err != nil {
		slog.Error("server listen error", "reason", err)
		cancel()
	}
}
