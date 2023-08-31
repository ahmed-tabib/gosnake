package main

import (
	"sync"
	"time"
)

type Statistics struct {
	StartTime time.Time

	Programs struct {
		TotalSeen int
		SeenMutex sync.Mutex
	}

	Subdomains struct {
		TotalFetched int
		FetchMutex   sync.Mutex
		TotalCrawled int
		CrawlMutex   sync.Mutex
	}

	Targets struct {
		TotalFetched  int
		FetchMutex    sync.Mutex
		TotalAttacked int
		AttackMutex   sync.Mutex
	}

	Vulns struct {
		TotalFound int
		FoundMutex sync.Mutex
	}
}
