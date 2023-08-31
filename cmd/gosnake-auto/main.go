package main

import (
	"fmt"
	"time"

	"automation.com/cachesnake"
)

func HandleResult(cfg *Config, result *cachesnake.AttackResult) {
	fmt.Println(result)
}

func main() {
	stats := &Statistics{StartTime: time.Now()}
	cfg := ReadConfig("config.yaml")

	start_message := "```[START]: Cachesnake Is Online.\n" + "[START]: At " + stats.StartTime.UTC().Format(time.RFC1123Z) + "```"
	NotifyDiscordWebhook(cfg.DiscordWebhookURL, start_message, false)

	return

	subdomain_channel := make(chan *cachesnake.Subdomain, 500)
	Stage1_Subdomains(cfg, stats, subdomain_channel)

	target_channel := make(chan *cachesnake.AttackTarget, 1000)
	Stage2_Targets(cfg, stats, subdomain_channel, target_channel)

	result_channel := make(chan *cachesnake.AttackResult, 10)
	Stage3_Attacks(cfg, stats, target_channel, result_channel)

	for {
		result := <-result_channel
		fmt.Println("Handling result....")
		HandleResult(cfg, result)
	}

}
