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
	target_channel := make(chan *cachesnake.AttackTarget, 1000)
	result_channel := make(chan *cachesnake.AttackResult, 10)

	stage1_params := StageParams{
		Cfg:           cfg,
		Stats:         stats,
		Notif:         notif,
		InputChannel:  nil,
		OutputChannel: subdomain_channel,
	}
	stage2_params := StageParams{
		Cfg:           cfg,
		Stats:         stats,
		Notif:         notif,
		InputChannel:  subdomain_channel,
		OutputChannel: target_channel,
	}
	stage3_params := StageParams{
		Cfg:           cfg,
		Stats:         stats,
		Notif:         notif,
		InputChannel:  target_channel,
		OutputChannel: result_channel,
	}

	Stage1_Subdomains(stage1_params)
	Stage2_Targets(stage2_params)
	Stage3_Attacks(stage3_params)

	for {
		result := <-stage3_params.OutputChannel.(chan *cachesnake.AttackResult)
		notif.SendStatusUpdate()
		notif.SendResult(result)
	}

}
