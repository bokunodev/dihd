package trie

import (
	"bufio"
	"os"
	"slices"
	"testing"
)

// random domains generated with https://mockaroo.com/
var domains = []string{
	"wunderground.com",
	"businessweek.com",
	"admin.ch",
	"ning.com",
	"baidu.com",
	"theatlantic.com",
	"moonfruit.com",
	"slideshare.net",
	"webeden.co.uk",
	"unc.edu",
	"csmonitor.com",
	"uiuc.edu",
	"google.co.jp",
	"nationalgeographic.com",
	"blogtalkradio.com",
	"vk.com",
	"columbia.edu",
	"senate.gov",
	"vkontakte.ru",
	"icq.com",
	"ovh.net",
	"google.com.br",
	"hatena.ne.jp",
	"cdc.gov",
	"gravatar.com",
	"is.gd",
	"flavors.me",
	"issuu.com",
	"goodreads.com",
	"sciencedirect.com",
	"plala.or.jp",
	"psu.edu",
	"sina.com.cn",
	"devhub.com",
	"freewebs.com",
	"youtube.com",
	"pen.io",
	"amazonaws.com",
	"hp.com",
	"google.com.br",
	"webmd.com",
	"addthis.com",
	"hc360.com",
	"myspace.com",
	"amazon.de",
	"xinhuanet.com",
	"yellowbook.com",
	"jugem.jp",
	"macromedia.com",
	"netlog.com",
	"canalblog.com",
	"cbc.ca",
	"elegantthemes.com",
	"mayoclinic.com",
	"alexa.com",
	"cnet.com",
	"netlog.com",
	"meetup.com",
	"ted.com",
	"ning.com",
	"dedecms.com",
	"oaic.gov.au",
	"sciencedirect.com",
	"cnn.com",
	"live.com",
	"google.com.au",
	"marketwatch.com",
	"techcrunch.com",
	"vkontakte.ru",
	"spotify.com",
	"youtu.be",
	"deviantart.com",
	"jalbum.net",
	"huffingtonpost.com",
	"xing.com",
	"mysql.com",
	"dailymotion.com",
	"google.co.jp",
	"yale.edu",
	"linkedin.com",
	"comcast.net",
	"qq.com",
	"newyorker.com",
	"bloomberg.com",
	"icq.com",
	"si.edu",
	"admin.ch",
	"blinklist.com",
	"prnewswire.com",
	"google.com.br",
	"purevolume.com",
	"biglobe.ne.jp",
	"arizona.edu",
	"acquirethisname.com",
	"gmpg.org",
	"spotify.com",
	"mozilla.com",
	"furl.net",
	"bizjournals.com",
	"elegantthemes.com",
}

func TestTrie(t *testing.T) {
	slices.Sort(domains)

	root := &Node{}

	for _, domain := range domains {
		Insert(root, Normalize(domain))
	}

	totalSize := root.Size() + headerSize
	slab := Marshal(root)
	if len(slab) != totalSize {
		t.Fatalf("expected calculated size doesnt match real size; expected %d got %d", totalSize, len(slab))
	}

	for _, domain := range domains {
		if !Search(slab, []byte(Normalize(domain))) {
			t.Fatalf("lookup failed; domain: %s", domain)
		}
	}
}

func BenchmarkTrie(b *testing.B) {
	f, err := os.Open("testdata/hblock-hosts_domains.txt")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = f.Close()
	})

	root := &Node{}

	scn := bufio.NewScanner(f)
	for scn.Scan() {
		err := scn.Err()
		if err != nil {
			b.Fatalf("an error occured while loading hosts file, error: %v", err)
		}

		Insert(root, Normalize(scn.Text()))
	}

	testKeywords := [][]byte{
		[]byte(".rf.ppatsohbew000-tsixe-tnseod"),                                              // 0
		[]byte(".sbs.pkcb9p-trohs-oot"),                                                       // 1
		[]byte(".moc.scnuyila.1-tsaehtuos-pa-sso.aknksjznx-ksakhsca-jkcsakjcsa-100"),          // 2
		[]byte(".moc.scnuyila.1-tsaehtuos-pa-sso.aknksjznx-ksakhsca-jkcsakjcsa-100-gnol-oot"), // 3
		[]byte(".moc.evihsemia.5615615652100"),                                                // 4
		[]byte(".moc.1626486100"),                                                             // 5
		[]byte(".moc.c73c6c7100"),                                                             // 6
		[]byte(".moc.x9100"),                                                                  // 7
	}

	slab := Marshal(root)

	b.ResetTimer()
	for b.Loop() {
		Search(slab, testKeywords[0])
		Search(slab, testKeywords[1])
		Search(slab, testKeywords[2])
		Search(slab, testKeywords[3])
		Search(slab, testKeywords[4])
		Search(slab, testKeywords[5])
		Search(slab, testKeywords[6])
		Search(slab, testKeywords[7])
	}
}
