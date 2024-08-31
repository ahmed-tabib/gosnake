package main

import (
	"flag"
	"log"
	"time"

	"automation.com/cachesnake"
)

func main() {
	cfg_file := flag.String("c", "config.yaml", "Path to the config file")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime)
	log.Println("[MAIN] CACHESNAKE STARTUP SEQUENCE BEGIN. CONFIG AT \"" + *cfg_file + "\"")

	stats := &Statistics{StartTime: time.Now()}
	cfg := ReadConfig(*cfg_file)

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

	log.Println("[MAIN] CACHESNAKE STARTUP SEQUENCE DONE.")

	for {
		result, ok := <-stage4_params.OutputChannel.(chan *cachesnake.AttackResult)

		if !ok {
			log.Println("[MAIN] Triage channel closed, exiting.")
			break
		}

		notif.SendResult(result)
		result = nil
	}

}
