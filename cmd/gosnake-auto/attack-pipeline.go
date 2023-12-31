package main

import (
	"context"
	"fmt"
	"slices"
	"time"

	"automation.com/cachesnake"
	"github.com/valyala/fasthttp"
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

			subs, err := FetchSubdomains(&program_list, client, 50, params.Cfg)

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

				params.Stats.Targets.FetchMutex.Lock()
				params.Stats.Targets.TotalFetched += 1
				params.Stats.Targets.FetchMutex.Unlock()

				result := cachesnake.RunAttacks(target, params.Cfg.Attack.Timeout, params.Cfg.Attack.Backoff, params.Cfg.UserAgent)

				params.Stats.Targets.AttackMutex.Lock()
				params.Stats.Targets.TotalAttacked += 1
				params.Stats.Targets.AttackMutex.Unlock()

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

func Stage4_Triage(params StageParams) {

	for i := 0; i < params.Cfg.Triage.Threads; i++ {

		go func() {
			for {
				result := <-params.InputChannel.(chan *cachesnake.AttackResult)

				true_positive_indices := make([]int, 0)
				header_bruteforce_count := 0
				for i, v := range result.VulnList {

					switch v.Name {
					case "Header Bruteforce":
						header_bruteforce_count += 1
						if len(v.OffendingHeaders) < 10 {
							true_positive_indices = append(true_positive_indices, i)
						}
					case "Reflected Cookie":
						true_positive_indices = append(true_positive_indices, i)
					default:
						if len(v.OffendingHeaders) < 5 {
							true_positive_indices = append(true_positive_indices, i)
						}
					}
				}

				new_vuln_list := make([]cachesnake.Vuln, len(true_positive_indices))
				for i := range new_vuln_list {
					new_vuln_list[i] = result.VulnList[true_positive_indices[i]]
				}

				result.VulnList = new_vuln_list

				if len(result.VulnList) > 0 && header_bruteforce_count < 10 {

					// Retry attacks to make sure they absolutely work
					triage_result := cachesnake.RunAttacks(result.Target, params.Cfg.Attack.Timeout, params.Cfg.Attack.Backoff, params.Cfg.UserAgent)

					vuln_intersection := make([]cachesnake.Vuln, 0, 10)
					for _, tv := range triage_result.VulnList {
						if tv.Name == "Header Bruteforce" {
							if slices.ContainsFunc(result.VulnList, func(v cachesnake.Vuln) bool {
								return v.Name == tv.Name && v.OffendingHeaders[0] == tv.OffendingHeaders[0]
							}) {
								vuln_intersection = append(vuln_intersection, tv)
							}
						}

						if slices.ContainsFunc(result.VulnList, func(v cachesnake.Vuln) bool { return v.Name == tv.Name }) {
							vuln_intersection = append(vuln_intersection, tv)
						}
					}

					if len(vuln_intersection) > 0 && len(vuln_intersection) < 15 {
						vuln_intersection = slices.CompactFunc(vuln_intersection, func(v1 cachesnake.Vuln, v2 cachesnake.Vuln) bool {
							return v1.Name == v2.Name && v1.OffendingHeaders[0] == v2.OffendingHeaders[0]
						})
						triage_result.VulnList = vuln_intersection
						params.OutputChannel.(chan *cachesnake.AttackResult) <- &triage_result

						params.Stats.Vulns.FoundMutex.Lock()
						params.Stats.Vulns.TotalFound++
						params.Stats.Vulns.FoundMutex.Unlock()
					}

					if triage_result.Target.InitialResponse != nil {
						fasthttp.ReleaseResponse(triage_result.Target.InitialResponse)
					}
				}

				if result.Target.InitialResponse != nil {
					fasthttp.ReleaseResponse(result.Target.InitialResponse)
				}
			}
		}()

	}

}
