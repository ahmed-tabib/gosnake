package main

import (
	"context"
	"fmt"
	"time"

	"automation.com/cachesnake"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type StageParams struct {
	Cfg           *Config
	Stats         *Statistics
	Notif         *Notify
	InputChannel  any
	OutputChannel any
}

func Stage1_Subdomains(params StageParams) {
	go func() {
		// setup db client
		client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(params.Cfg.Mongo.URI))
		if err != nil {
			params.Notif.SendImmediate("```--------[FATAL ERROR]--------\nFailed to create MongoDB client.\n[Error Message]: " + fmt.Sprint(err) + "```")
			panic(err)
		}

		program_list := make(map[string]*cachesnake.BBProgram)

		//infinite loop, fetching subdomains
		err_count := 0
		for {

			subs, err := FetchSubdomains(&program_list, client, 500, params.Cfg)

			// if err retry, if persists panic
			if err != nil {
				err_count++

				if err_count > 10 {
					params.Notif.SendImmediate("```--------[FATAL ERROR]--------\nFetching Subdomains resulted in an error more than 10 times in a row.\n[Error Message]: " + fmt.Sprint(err) + "```")
					panic(err)
				}

				continue
			}
			err_count = 0

			// Update stats
			if params.Stats.Programs.SeenMutex.TryLock() {
				params.Stats.Programs.TotalSeen += len(program_list) - params.Stats.Programs.TotalSeen
				params.Stats.Programs.SeenMutex.Unlock()
			}
			if len(subs) > 0 {
				params.Stats.Subdomains.FetchMutex.Lock()
				params.Stats.Subdomains.TotalFetched += len(subs)
				params.Stats.Subdomains.FetchMutex.Unlock()
			} else {
				params.Notif.SendLowPriority("```------------[NOTICE]------------\nOut of subdomains, sleeping for 10 minutes.\nCurrent time is: " + time.Now().UTC().Format(time.RFC3339) + "```")
				time.Sleep(10 * time.Minute)
				continue
			}

			// finally, output the subdomains
			for _, subdomain := range subs {
				params.OutputChannel.(chan *cachesnake.Subdomain) <- subdomain
			}

		}
	}()
}

func Stage2_Targets(params StageParams) {

	for i := 0; i < params.Cfg.Crawler.Threads; i++ {

		go func() {
			subdomain := make([]*cachesnake.Subdomain, 1, 1)

			for {
				subdomain[0] = <-params.InputChannel.(chan *cachesnake.Subdomain)
				cachesnake.GenerateTargets(subdomain, params.Cfg.Crawler.TargetsPerSubdomain, params.Cfg.Crawler.Timeout, params.Cfg.Crawler.Backoff, params.Cfg.UserAgent, params.Cfg.Crawler.Regexes, params.OutputChannel.(chan *cachesnake.AttackTarget))

				params.Stats.Subdomains.CrawlMutex.Lock()
				params.Stats.Subdomains.TotalCrawled++
				params.Stats.Subdomains.CrawlMutex.Unlock()
			}
		}()

	}

}

func Stage3_Attacks(params StageParams) {

	for i := 0; i < params.Cfg.Attack.Threads; i++ {

		go func() {
			for {
				target := <-params.InputChannel.(chan *cachesnake.AttackTarget)
				result := cachesnake.RunAttacks(target, params.Cfg.Attack.Timeout, params.Cfg.Attack.Backoff, params.Cfg.UserAgent)

				if len(result.VulnList) > 0 {
					params.OutputChannel.(chan *cachesnake.AttackResult) <- &result

					params.Stats.Vulns.FoundMutex.Lock()
					params.Stats.Vulns.TotalFound++
					params.Stats.Vulns.FoundMutex.Unlock()
				}
			}
		}()

	}

}