package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"automation.com/cachesnake"
)

func main() {
	cfg_file := flag.String("c", "config.yaml", "Path to the config file")
	flag.Parse()

	log_file, err := os.OpenFile("gosnake.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal("Could not open gosnake.log")
	}

	log.SetFlags(log.Ldate | log.Ltime)
	log.SetOutput(log_file)
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

		log.Println("[MAIN] INCOMING VULN REPORT")
		message := "----------[VULN REPORT]----------\n" +
			"[Current Time]: " + time.Now().UTC().Format(time.RFC3339) + "\n" +
			"[Attack Started]: " + result.TimeStarted.UTC().Format(time.RFC3339) + "\n" +
			"[Attack Stopped]: " + result.TimeStopped.UTC().Format(time.RFC3339) + "\n" +
			"[Time Elapsed]: " + result.TimeStopped.Sub(result.TimeStarted).Round(time.Millisecond).String() + "\n\n" +

			"[Program Info]: \n" +
			"    Name:         " + result.Target.ParentSubdomain.ParentProgram.ProgramName + "\n" +
			"    Platform:     " + result.Target.ParentSubdomain.ParentProgram.Platform + "\n" +
			"    Program URL:  " + result.Target.ParentSubdomain.ParentProgram.ProgramURL + "\n" +
			"    Has Bounties: " + fmt.Sprint(result.Target.ParentSubdomain.ParentProgram.OffersBounties) + "\n\n" +

			"[Target Info]: \n" +
			"    Subdomain: " + result.Target.ParentSubdomain.Value + "\n" +
			"    URL: \"" + result.Target.TargetURL + "\"\n\n" +

			"[Vulns Found]: " + fmt.Sprint(len(result.VulnList)) + "\n\n"

		for i, v := range result.VulnList {
			message += fmt.Sprintf("[Vuln %d]: \n", i+1) +
				"    Name:    " + v.Name + "\n" +
				"    Details: " + v.Details + "\n" +
				"    Headers: \n"
			for _, h := range v.OffendingHeaders {
				message += "        \"" + h + "\"\n"
			}
			message += "    Impact: " + fmt.Sprint(v.Impact) + "\n" +
				"    Found At: " + v.TimeFound.Format(time.RFC3339) + "\n\n"
		}

		log.Print(message)

		notif.SendResult(result)
		result = nil
	}

}
