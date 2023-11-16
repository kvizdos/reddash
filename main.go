package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/kvizdos/reddash/enumerators/web/fuzzing"
	"github.com/kvizdos/reddash/wordlists"
)

var fuzzMgr *fuzzing.FuzzManager

func fuzzHandler(w http.ResponseWriter, r *http.Request) {
	fuzzers := fuzzMgr.ActiveFuzzers()

	running := "Running:\n"
	queued := "Queued:\n"
	complete := "Complete:\n"

	for name, fuzzInfo := range fuzzers {
		switch fuzzInfo.Status {
		case fuzzing.QUEUED:
			queued = queued + fmt.Sprintf("%s\n", name)
			break
		case fuzzing.RUNNING:
			running = running + fmt.Sprintf("%s (%s): %d of %d - Found %d\n", name, fuzzInfo.Type, fuzzInfo.Progress, fuzzInfo.Total, len(fuzzInfo.Hits))
			if len(fuzzInfo.Hits) > 0 {
				for _, hit := range fuzzInfo.Hits {
					running += fmt.Sprintf("- %s (%d)\n", hit.Title, hit.StatusCode)
				}
			}
			break
		case fuzzing.COMPLETE:
			complete = complete + fmt.Sprintf("%s (%s): %d of %d - Found %d\n", name, fuzzInfo.Type, fuzzInfo.Progress, fuzzInfo.Total, len(fuzzInfo.Hits))
			if len(fuzzInfo.Hits) > 0 {
				for _, hit := range fuzzInfo.Hits {
					complete += fmt.Sprintf("- %s (%d)\n", hit.Title, hit.StatusCode)
				}
			}
		}
	}

	digraph := fuzzMgr.GetDigraph()
	w.Write([]byte(fmt.Sprintf("%s\n%s\n%s\n\nDigraph:\n%s", running, queued, complete, digraph)))
}

func main() {
	directoriesWordList, err := wordlists.ReadWordList("./wordlists_dir/test.txt")

	if err != nil {
		panic(err)
	}
	fuzzMgr = fuzzing.NewFuzzManager(1, 1)

	go fuzzMgr.AddFuzzer("Directory Enumeration", "http://example.lan:8080", directoriesWordList, fuzzing.DIRECTORY)
	go fuzzMgr.AddFuzzer("Subdomain Enumeration", "http://example.lan:8080", directoriesWordList, fuzzing.SUBDOMAIN)

	http.HandleFunc("/", fuzzHandler)
	log.Fatal(http.ListenAndServe(":9090", nil))
}
