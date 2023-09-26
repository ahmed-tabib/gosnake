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

	go func() { time.Sleep(time.Minute * 2); notif.SendStatusUpdate() }()

	subdomain_channel := make(chan *cachesnake.Subdomain, 50)
	target_channel := make(chan *cachesnake.AttackTarget, 700)
	result_channel := make(chan *cachesnake.AttackResult, 20)
	triage_channel := make(chan *cachesnake.AttackResult, 10)

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
	stage4_params := StageParams{
		Cfg:           cfg,
		Stats:         stats,
		Notif:         notif,
		InputChannel:  result_channel,
		OutputChannel: triage_channel,
	}

	Stage1_Subdomains(stage1_params)
	Stage2_Targets(stage2_params)
	Stage3_Attacks(stage3_params)
	Stage4_Triage(stage4_params)

	for {
		result := <-stage4_params.OutputChannel.(chan *cachesnake.AttackResult)
		notif.SendResult(result)
		result = nil
	}

}
