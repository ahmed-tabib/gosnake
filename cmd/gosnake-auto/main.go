package main

import (
	"time"

	"automation.com/cachesnake"
)

func main() {
	stats := &Statistics{StartTime: time.Now()}
	cfg := ReadConfig("config.yaml")

	notif := &Notify{}
	notif.Init(cfg, stats, true)

	subdomain_channel := make(chan *cachesnake.Subdomain, 500)
	Stage1_Subdomains(cfg, stats, subdomain_channel)

	target_channel := make(chan *cachesnake.AttackTarget, 1000)
	Stage2_Targets(cfg, stats, subdomain_channel, target_channel)

	result_channel := make(chan *cachesnake.AttackResult, 10)
	Stage3_Attacks(cfg, stats, target_channel, result_channel)

	for {
		result := <-result_channel
		notif.SendResult(result)
	}

}
