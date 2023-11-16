package fuzzing

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

func FuzzWebSubdomains(targetURL string, opts WebFuzzOptions) {
	var wg sync.WaitGroup

	fmt.Printf("Starting Web Subdomain Fuzz with %d total items.\n", len(opts.WordList))

	split := strings.Split(targetURL, "://")
	proto := split[0]
	target := split[1]

	for _, word := range opts.WordList {
		if err := opts.RequestsSemaphore.Acquire(context.Background(), 1); err != nil {
			panic(err)
		}
		wg.Add(1)
		go func(word string) {
			defer opts.RequestsSemaphore.Release(1)
			defer wg.Done()

			hit, found := makeSubdomainRequest(proto, target, word)
			if found {
				opts.HitsChan <- hit
			}
			opts.ProgressChan <- 1
			time.Sleep(100 * time.Millisecond)
		}(word)
	}

	wg.Wait() // wait for all goroutines to complete
	opts.DoneChan <- true
}

func makeSubdomainRequest(protocol string, targetURL string, subdomain string) (FuzzHit, bool) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s://%s", protocol, targetURL), nil)
	if err != nil {
		fmt.Printf("error making http request: %s\n", err)
		return FuzzHit{}, false
	}

	target := strings.Split(targetURL, "/")[0]

	req.Host = fmt.Sprintf("%s.%s", subdomain, target)

	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}
	res, err := client.Do(req)
	if err != nil {
		time.Sleep(100 * time.Millisecond)
		makeSubdomainRequest(protocol, targetURL, subdomain)
	}
	defer res.Body.Close()

	if res.StatusCode != 404 {
		return FuzzHit{
			Title:      protocol + "://" + req.Host,
			StatusCode: res.StatusCode,
		}, true
	}

	return FuzzHit{}, false
}
