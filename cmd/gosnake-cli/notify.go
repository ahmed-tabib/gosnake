package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"automation.com/cachesnake"
)

type Notify struct {
	cfg   *Config
	stats *Statistics

	topPriorityChannel chan string
	midPriorityChannel chan string
	lowPriorityChannel chan string

	isInit bool
}

func (n *Notify) Init(cfg *Config, stats *Statistics, send_startup_msg bool) {
	if n.isInit {
		return
	}

	n.cfg = cfg
	n.stats = stats

	if send_startup_msg {
		n.SendImmediate("```[START]: Cachesnake Is Online.\n" + "[START]: At " + stats.StartTime.UTC().Format(time.RFC1123Z) + "```")
	}

	n.topPriorityChannel = make(chan string, 20)
	n.midPriorityChannel = make(chan string, 100)
	n.lowPriorityChannel = make(chan string, 500)

	// Main notification thread, establishes priority and prevents overlap of messages
	go func() {
		for {
			select {
			case msg := <-n.topPriorityChannel:
				NotifyDiscordWebhook(n.cfg.Notifications.WebhookURL, msg, true)
				continue
			default:
			}

			select {
			case msg := <-n.midPriorityChannel:
				NotifyDiscordWebhook(n.cfg.Notifications.WebhookURL, msg, false)
				continue
			default:
			}

			select {
			case msg := <-n.topPriorityChannel:
				NotifyDiscordWebhook(n.cfg.Notifications.WebhookURL, msg, true)
			case msg := <-n.midPriorityChannel:
				NotifyDiscordWebhook(n.cfg.Notifications.WebhookURL, msg, false)
			case msg := <-n.lowPriorityChannel:
				NotifyDiscordWebhook(n.cfg.Notifications.WebhookURL, msg, false)
			}
		}
	}()

	// Status update goroutine
	go func() {

		if !n.cfg.Notifications.SendStatus {
			return
		}

		tick := time.Tick(n.cfg.Notifications.StatusInterval)

		// Do it by interval or by time of day
		if tick != nil {
			for {
				select {
				case <-tick:
					n.SendStatusUpdate()
				}
			}

		} else {
			if len(n.cfg.Notifications.StatusAt) == 0 {
				return
			}

			for {
				// figure out how long we have to sleep til the nearest trigger time
				now := time.Now().UTC()
				sleep_duration := time.Duration(0)
				now_yyyy_mm_dd := fmt.Sprintf("%d-%02d-%02d", now.Year(), int(now.Month()), now.Day())

				for _, t := range n.cfg.Notifications.StatusAt {

					status_update_time, _ := time.Parse(time.RFC3339, now_yyyy_mm_dd+"T"+t+"Z")
					diff := status_update_time.Sub(now)

					if diff <= time.Duration(0) {
						diff += 24 * time.Hour
					}

					if sleep_duration <= time.Duration(0) || diff < sleep_duration {
						sleep_duration = diff
					}
				}

				// zzzzzzz
				time.Sleep(sleep_duration)

				// wakeup and do it all over again
				n.SendStatusUpdate()
			}

		}

	}()

	n.isInit = true
}

func (n *Notify) SendImmediate(message string) {
	NotifyDiscordWebhook(n.cfg.Notifications.WebhookURL, message, true)
}

func (n *Notify) SendTopPriority(message string) {
	if !n.isInit {
		return
	}

	n.topPriorityChannel <- message
}

func (n *Notify) SendMidPriority(message string) {
	if !n.isInit {
		return
	}

	go func() { n.midPriorityChannel <- message }()
}

func (n *Notify) SendLowPriority(message string) {
	if !n.isInit {
		return
	}

	go func() { n.lowPriorityChannel <- message }()
}

func (n *Notify) SendStatusUpdate() {
	message := "```----------[STATUS UPDATE]----------\n" +
		"[Current Time]: " + time.Now().UTC().Format(time.RFC3339) + "\n" +
		"[Time Started]: " + n.stats.StartTime.UTC().Format(time.RFC3339) + "\n" +
		"[Uptime]: " + time.Since(n.stats.StartTime).Round(time.Millisecond).String() + "\n" +
		"[Programs]: \n" +
		"    Seen: " + fmt.Sprint(n.stats.Programs.TotalSeen) + "\n" +
		"[Subdomains]: \n" +
		"    Fetched: " + fmt.Sprint(n.stats.Subdomains.TotalFetched) + "\n" +
		"    Crawled: " + fmt.Sprint(n.stats.Subdomains.TotalCrawled) + "\n" +
		"[Targets]: \n" +
		"    Fetched:  " + fmt.Sprint(n.stats.Targets.TotalFetched) + "\n" +
		"    Attacked: " + fmt.Sprint(n.stats.Targets.TotalAttacked) + "\n" +
		"[Vulnerabilites]: \n" +
		"    Found: " + fmt.Sprint(n.stats.Vulns.TotalFound) + "\n" +
		"----------[END OF UPDATE]----------```"

	n.SendMidPriority(message)
}

func (n *Notify) SendResult(r *cachesnake.AttackResult) {
	message := "```----------[VULN REPORT]----------\n" +
		"[Current Time]: " + time.Now().UTC().Format(time.RFC3339) + "\n" +
		"[Attack Started]: " + r.TimeStarted.UTC().Format(time.RFC3339) + "\n" +
		"[Attack Stopped]: " + r.TimeStopped.UTC().Format(time.RFC3339) + "\n" +
		"[Time Elapsed]: " + r.TimeStopped.Sub(r.TimeStarted).Round(time.Millisecond).String() + "\n\n" +

		"[Program Info]: \n" +
		"    Name:         " + r.Target.ParentSubdomain.ParentProgram.ProgramName + "\n" +
		"    Platform:     " + r.Target.ParentSubdomain.ParentProgram.Platform + "\n" +
		"    Program URL:  " + r.Target.ParentSubdomain.ParentProgram.ProgramURL + "\n" +
		"    Has Bounties: " + fmt.Sprint(r.Target.ParentSubdomain.ParentProgram.OffersBounties) + "\n\n" +

		"[Target Info]: \n" +
		"    Subdomain: " + r.Target.ParentSubdomain.Value + "\n" +
		"    URL: \"" + r.Target.TargetURL + "\"\n\n" +

		"[Vulns Found]: " + fmt.Sprint(len(r.VulnList)) + "\n\n"

	for i, v := range r.VulnList {
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

	message += "```"

	if len(message) <= 2000 {
		n.SendTopPriority(message)
	} else {
		lines := strings.Split(message, "\n")
		tmp_msg := ""
		msg_list := make([]string, 0, (len(message)/2000)+1)

		for _, line := range lines {

			if len(tmp_msg)+len(line) > 2000 {
				msg_list = append(msg_list, tmp_msg)
				tmp_msg = ""
			}

			tmp_msg += line
		}

		if len(tmp_msg) > 0 {
			msg_list = append(msg_list, tmp_msg)
		}

		for _, msg := range msg_list {
			n.SendTopPriority(msg)
		}
	}
}

func NotifyDiscordWebhook(webhook_url string, message string, ping_everyone bool) error {

	data := make(map[string]interface{})

	if ping_everyone {
		message = "@everyone\n" + message
		data["allowed_mentions"] = map[string]interface{}{"parse": []string{"everyone"}}
	}

	data["content"] = message

	json_data, err := json.Marshal(data)
	if err != nil {
		return err
	}

	resp, err := http.Post(webhook_url, "application/json", bytes.NewBuffer(json_data))
	if err != nil {
		return err
	}
	resp.Body.Close()

	return nil
}
