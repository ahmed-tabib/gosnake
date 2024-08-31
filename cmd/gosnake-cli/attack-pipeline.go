package main

import (
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"automation.com/cachesnake"
	"github.com/valyala/fasthttp"
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

		subdomain_file_content, err := os.ReadFile(params.Cfg.SubdomainFile)
		if err != nil {
			params.Notif.SendImmediate("```--------[FATAL ERROR]--------\nFailed to read subdomain file.\n[Error Message]: " + fmt.Sprint(err) + "```")
			log.Fatal(err)
		}

		raw_subdomain_list := strings.Split(string(subdomain_file_content), "\n")

		program := &cachesnake.BBProgram{
			ProgramName:    "N/A",
			ProgramURL:     "N/A",
			Platform:       "N/A",
			OffersBounties: false,
			InScope:        []string{},
			OutOfScope:     []string{},
		}

		subdomain_list := make([]*cachesnake.Subdomain, 0, len(raw_subdomain_list))

		for _, raw_sub := range raw_subdomain_list {
			subdomain := cachesnake.Subdomain{
				Value:         strings.TrimSpace(raw_sub),
				ParentProgram: program,
				LastRequested: time.Now(),
				SubLock:       sync.Mutex{},
				CookieList:    make([]*fasthttp.Cookie, 0),
			}
			subdomain_list = append(subdomain_list, &subdomain)
		}

		if len(subdomain_list) > 0 {
			params.Stats.Subdomains.TotalFetched += len(subdomain_list)
		} else {
			params.Notif.SendLowPriority("```------------[NOTICE]------------\nNo Subdomains in file. Exiting.```")
			log.Fatal("Subdomain File empty")
		}
		// finally, output the subdomains
		for _, subdomain := range subdomain_list {
			params.OutputChannel.(chan *cachesnake.Subdomain) <- subdomain
		}

		close(params.OutputChannel.(chan *cachesnake.Subdomain))

		params.Notif.SendLowPriority("```------------[NOTICE]------------\nAll subdomains sent.```")
		log.Println("All subdomains sent")
	}()
}

func Stage2_Targets(params StageParams) {
	var wg sync.WaitGroup

	for i := 0; i < params.Cfg.Crawler.Threads; i++ {
		wg.Add(1)

		go func(ThreadIdx int) {
			defer wg.Done()

			subdomain := make([]*cachesnake.Subdomain, 1)

			for {
				var ok bool
				subdomain[0], ok = <-params.InputChannel.(chan *cachesnake.Subdomain)

				if !ok {
					log.Printf("[Target-Thread:%d] Subdomain channel closed, Target Goroutine %d exiting.\n", ThreadIdx, ThreadIdx)
					break
				}

				log.Printf("[Target-Thread:%d] Generating targets for subdomain \"%v\"\n", ThreadIdx, subdomain[0].Value)
				cachesnake.GenerateTargets(subdomain, params.Cfg.Crawler.TargetsPerSubdomain, params.Cfg.Crawler.Timeout, params.Cfg.Crawler.Backoff, params.Cfg.UserAgent, params.Cfg.Crawler.Regexes, params.OutputChannel.(chan *cachesnake.AttackTarget))

				params.Stats.Subdomains.CrawlMutex.Lock()
				params.Stats.Subdomains.TotalCrawled++
				params.Stats.Subdomains.CrawlMutex.Unlock()
			}
		}(i)
	}

	//When all the goroutines exit (because the input channel is closed & empty) we can close the output channel
	go func() {
		wg.Wait()                                                   // Wait for all goroutines to finish
		close(params.OutputChannel.(chan *cachesnake.AttackTarget)) // Close the channel
	}()
}

func Stage3_Attacks(params StageParams) {
	var wg sync.WaitGroup

	for i := 0; i < params.Cfg.Attack.Threads; i++ {
		wg.Add(1)

		go func(ThreadIdx int) {
			defer wg.Done()
			for {
				target, ok := <-params.InputChannel.(chan *cachesnake.AttackTarget)

				if !ok {
					log.Printf("[Attack-Thread:%d] Target channel closed, Attack Goroutine %d exiting.\n", ThreadIdx, ThreadIdx)
					break
				}

				log.Printf("[Attack-Thread:%d] Attacking target \"%v\"\n", ThreadIdx, target.TargetURL)

				params.Stats.Targets.FetchMutex.Lock()
				params.Stats.Targets.TotalFetched += 1
				params.Stats.Targets.FetchMutex.Unlock()

				result := cachesnake.RunAttacks(target, params.Cfg.Attack.Timeout, params.Cfg.Attack.Backoff, params.Cfg.UserAgent)

				params.Stats.Targets.AttackMutex.Lock()
				params.Stats.Targets.TotalAttacked += 1
				params.Stats.Targets.AttackMutex.Unlock()

				log.Printf("[Attack-Thread:%d] Done Attacking target \"%v\"\n", ThreadIdx, target.TargetURL)

				if len(result.VulnList) > 0 {
					params.OutputChannel.(chan *cachesnake.AttackResult) <- &result

					log.Printf("[Attack-Thread:%d] Target may be vulnerable. Sending to Triage\n", ThreadIdx)

					params.Stats.Vulns.FoundMutex.Lock()
					params.Stats.Vulns.TotalFound++
					params.Stats.Vulns.FoundMutex.Unlock()
				}
			}
		}(i)
	}

	//When all the goroutines exit (because the input channel is closed & empty) we can close the output channel
	go func() {
		wg.Wait()                                                   // Wait for all goroutines to finish
		close(params.OutputChannel.(chan *cachesnake.AttackResult)) // Close the channel
	}()
}

func Stage4_Triage(params StageParams) {
	var wg sync.WaitGroup

	for i := 0; i < params.Cfg.Triage.Threads; i++ {
		wg.Add(1)

		go func(ThreadIdx int) {
			defer wg.Done()

			for {
				result, ok := <-params.InputChannel.(chan *cachesnake.AttackResult)

				if !ok {
					log.Printf("[Triage-Thread:%d] Vuln channel closed, Triage Goroutine %d exiting.\n", ThreadIdx, ThreadIdx)
					break
				}

				log.Printf("[Triage-Thread:%d] Triaging target vulns \"%v\"\n", ThreadIdx, result.Target.TargetURL)

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
		}(i)
	}

	//When all the goroutines exit (because the input channel is closed & empty) we can close the output channel
	go func() {
		wg.Wait()                                                   // Wait for all goroutines to finish
		close(params.OutputChannel.(chan *cachesnake.AttackResult)) // Close the channel
	}()
}
