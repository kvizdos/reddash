package fuzzing

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

type WebFuzzOptions struct {
	RequestsSemaphore *semaphore.Weighted
	UserAgent         string // customizable UA
	DoneChan          chan bool
	WordList          []string
	TryExtensions     []string
	ProgressChan      chan<- int     // channel to send progress updates
	HitsChan          chan<- FuzzHit // channel to send found paths
}

func FuzzWebDirectories(targetURL string, opts WebFuzzOptions) {
	var wg sync.WaitGroup

	fmt.Printf("Starting Web Directory Fuzz with %d total items.\n", len(opts.WordList))

	for _, word := range opts.WordList {
		if err := opts.RequestsSemaphore.Acquire(context.Background(), 1); err != nil {
			fmt.Println(err)
		}
		wg.Add(1)

		go func(word string) {
			defer opts.RequestsSemaphore.Release(1)
			defer wg.Done()
			hit, found := makeRequest(targetURL, word)
			if found {
				opts.HitsChan <- hit
			}
			opts.ProgressChan <- 1
			time.Sleep(100 * time.Millisecond)
		}(word)

		// Then try the word with each extension
		for _, ext := range opts.TryExtensions {
			if err := opts.RequestsSemaphore.Acquire(context.Background(), 1); err != nil {
				panic(err)
			}

			wg.Add(1)

			go func(word, ext string) {
				defer opts.RequestsSemaphore.Release(1)
				defer wg.Done()

				hit, found := makeRequest(targetURL, fmt.Sprintf("%s.%s", word, ext))
				if found {
					opts.HitsChan <- hit
				}
				opts.ProgressChan <- 1
				time.Sleep(100 * time.Millisecond)
			}(word, ext)
		}
	}

	wg.Wait() // wait for all goroutines to complete
	opts.DoneChan <- true
}

func makeRequest(targetURL, path string) (FuzzHit, bool) {
	redirection := ""
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirection = req.URL.String()
			return nil
		},
	}

	target := strings.Split(targetURL, ".")

	protoStripped := strings.Split(targetURL, "://")

	useTarget := targetURL
	if len(target) > 2 {
		target = target[len(target)-2:]
		useTarget = fmt.Sprintf("%s://%s", protoStripped[0], strings.Join(target, "."))
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s", useTarget, path), nil)

	host := strings.Split(protoStripped[1], "/")
	req.Host = host[0]

	if err != nil {
		fmt.Printf("error making http request: %s\n", err)
		os.Exit(1)
	}

	res, err := client.Do(req)
	if err != nil {
		time.Sleep(100 * time.Millisecond)
		fmt.Println(err)
		return makeRequest(targetURL, path)
	}
	defer res.Body.Close()

	if res.StatusCode != 404 {
		if res.StatusCode == http.StatusTemporaryRedirect || res.StatusCode == http.StatusPermanentRedirect {
			fmt.Println("in here!")
		}
		return FuzzHit{
			Title:      fmt.Sprintf("%s/%s", targetURL, path),
			StatusCode: res.StatusCode,
			Redirect:   redirection,
		}, true
	}

	return FuzzHit{}, false
}
