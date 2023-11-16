package fuzzing

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/sync/semaphore"
)

type FuzzType string

const (
	DIRECTORY FuzzType = "dir"
	SUBDOMAIN FuzzType = "sub"
)

var Fuzzers = map[FuzzType]func(target string, options WebFuzzOptions){
	DIRECTORY: FuzzWebDirectories,
	SUBDOMAIN: FuzzWebSubdomains,
}

type FuzzHit struct {
	Title      string // path / subdomain
	StatusCode int
	Redirect   string // if its a redirect, this is the link.
}

type FuzzStatus string

const (
	QUEUED   FuzzStatus = "queued"
	RUNNING  FuzzStatus = "running"
	COMPLETE FuzzStatus = "complete"
)

type FuzzTask struct {
	Name        string
	Status      FuzzStatus
	Progress    int
	Total       int
	DoneChannel chan bool `json:"-"`
	Hits        []FuzzHit
	Type        FuzzType
	Target      string
}

type FuzzManager struct {
	sem               *semaphore.Weighted
	tasks             map[string]*FuzzTask
	mu                sync.Mutex
	discoveredTargets map[string]bool // map[targetURL]hasBeenScraped
	activeFuzzers     *semaphore.Weighted
}

func NewFuzzManager(maxConnections int, maxConcurrency int) *FuzzManager {
	return &FuzzManager{
		sem:           semaphore.NewWeighted(int64(maxConnections)),
		tasks:         make(map[string]*FuzzTask),
		activeFuzzers: semaphore.NewWeighted(int64(maxConcurrency)),
	}
}

func (fm *FuzzManager) GetDigraph() string {
	output := convertToDigraph(fm.tasks)

	return output
}

func (fm *FuzzManager) AddFuzzer(name string, target string, wordlist []string, fuzzType FuzzType) {
	fm.mu.Lock()
	if _, exists := fm.tasks[name]; exists {
		fmt.Println("Fuzzer with this name already exists")
		return
	}
	fm.mu.Unlock()

	progressChan := make(chan int)
	doneChan := make(chan bool)
	hitChan := make(chan FuzzHit)

	task := &FuzzTask{
		Name:        name,
		Status:      QUEUED,
		Progress:    0,
		Total:       len(wordlist),
		DoneChannel: doneChan,
		Type:        fuzzType,
		Target:      target,
	}
	fm.mu.Lock()
	fm.tasks[name] = task
	fm.mu.Unlock()

	fmt.Println("Waiting for a free Semaphore", name, "...")
	if err := fm.activeFuzzers.Acquire(context.Background(), 1); err != nil {
		panic(err)
	}
	fmt.Println("Running", name)

	fm.mu.Lock()
	fm.tasks[name].Status = RUNNING
	fm.mu.Unlock()

	fuzzerFunc := Fuzzers[fuzzType]

	go fuzzerFunc(target, WebFuzzOptions{
		RequestsSemaphore: fm.sem,
		UserAgent:         "",
		DoneChan:          task.DoneChannel,
		WordList:          wordlist,
		TryExtensions:     []string{},
		ProgressChan:      progressChan,
		HitsChan:          hitChan,
	})

	go func() {
		for {
			select {
			case progress := <-progressChan:
				task.Progress += progress
			case hit := <-hitChan:
				task.Hits = append(task.Hits, hit)

				fm.mu.Lock()

				if fm.discoveredTargets == nil {
					fm.discoveredTargets = map[string]bool{}
				}

				if _, exists := fm.discoveredTargets[hit.Title]; !exists {
					fm.discoveredTargets[hit.Title] = true
					fm.mu.Unlock()

					go fm.AddFuzzer(fmt.Sprintf("[AUTO] %s", hit.Title), hit.Title, wordlist, DIRECTORY)
				} else {
					fm.mu.Unlock()
				}

			case <-doneChan:
				fm.mu.Lock()
				fm.tasks[name].Status = COMPLETE
				fm.activeFuzzers.Release(1)
				fm.mu.Unlock()
				return
			}
		}
	}()
}

func (fm *FuzzManager) ActiveFuzzers() map[string]*FuzzTask {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	activeTasks := make(map[string]*FuzzTask)
	for name, task := range fm.tasks {
		activeTasks[name] = task
	}
	return activeTasks
}

func (fm *FuzzManager) Progress(name string) (int, int, bool) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	task, exists := fm.tasks[name]
	if !exists {
		return 0, 0, false
	}
	return task.Progress, task.Total, true
}
