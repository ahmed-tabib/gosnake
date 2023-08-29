package main

import (
	"fmt"

	"automation.com/cachesnake"
)

func HandleResult(cfg *Config, result *cachesnake.AttackResult) {
	fmt.Println(result)
}

func main() {
	fmt.Println("Hello, World!")

	cfg := ReadConfig("config.yaml")

	subdomain_channel := make(chan *cachesnake.Subdomain, 500)
	Stage1_Subdomains(cfg, subdomain_channel)

	target_channel := make(chan *cachesnake.AttackTarget, 1000)
	Stage2_Targets(cfg, subdomain_channel, target_channel)

	result_channel := make(chan *cachesnake.AttackResult, 10)
	Stage3_Attacks(cfg, target_channel, result_channel)

	for {
		result := <-result_channel
		fmt.Println("Handling result....")
		HandleResult(cfg, result)
	}

}
