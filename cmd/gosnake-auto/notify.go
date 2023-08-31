package main

import (
	"bytes"
	"encoding/json"
	"net/http"
)

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
