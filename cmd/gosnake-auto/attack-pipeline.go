package main

import (
	"context"

	"automation.com/cachesnake"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func Stage1_Subdomains(cfg *Config, sub_chan chan<- *cachesnake.Subdomain) {
	go func() {
		// setup db client
		client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(cfg.Mongo.URI))
		if err != nil {
			panic(err)
		}

		program_list := make(map[string]*cachesnake.BBProgram)

		//infinite loop, fetching subdomains
		err_count := 0
		for {

			subs, err := FetchSubdomains(&program_list, client, 500, cfg)

			// if err retry, if persists panic
			if err != nil {
				err_count++

				if err_count > 10 {
					panic(err)
				}

				continue
			}
			err_count = 0

			// finally, output the subdomains
			for _, subdomain := range subs {
				sub_chan <- subdomain
			}

		}
	}()
}

func Stage2_Targets(cfg *Config, sub_chan <-chan *cachesnake.Subdomain, target_chan chan<- *cachesnake.AttackTarget) {
	for i := 0; i < cfg.Crawler.Threads; i++ {
		go func() {
			subdomain := make([]*cachesnake.Subdomain, 1, 1)

			for {
				subdomain[0] = <-sub_chan
				cachesnake.GenerateTargets(subdomain, cfg.Crawler.TargetsPerSubdomain, cfg.Crawler.Timeout, cfg.Crawler.Backoff, cfg.UserAgent, cfg.Crawler.Regexes, target_chan)
			}
		}()
	}
}

func Stage3_Attacks(cfg *Config, target_chan <-chan *cachesnake.AttackTarget, result_chan chan<- *cachesnake.AttackResult) {
	for i := 0; i < cfg.Attack.Threads; i++ {
		go func() {
			for {
				target := <-target_chan
				result := cachesnake.RunAttacks(target, cfg.Attack.Timeout, cfg.Attack.Backoff, cfg.UserAgent)

				if len(result.VulnList) > 0 {
					result_chan <- &result
				}
			}
		}()
	}
}
