package main

import (
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	SubdomainFile string

	Crawler struct {
		Timeout             time.Duration
		Backoff             time.Duration
		Threads             int
		Regexes             []*regexp.Regexp
		TargetsPerSubdomain int
		MinSubdomainAge     time.Duration
	}

	Attack struct {
		Timeout time.Duration
		Backoff time.Duration
		Threads int
	}

	Triage struct {
		Threads int
	}

	Notifications struct {
		WebhookURL     string
		SendStatus     bool
		StatusInterval time.Duration
		StatusAt       []string
	}

	UserAgent string
}

func (cfg *Config) UnmarshalYAML(value *yaml.Node) error {
	custom_struct := struct {
		SubdomainFile string `yaml:"subdomain_file"`

		Crawler struct {
			Timeout             string   `yaml:"timeout"`
			Backoff             string   `yaml:"backoff"`
			Threads             int      `yaml:"threads"`
			Regexes             []string `yaml:"regexes"`
			TargetsPerSubdomain int      `yaml:"targets_per_subdomain"`
			MinSubdomainAge     string   `yaml:"min_subdomain_age"`
		} `yaml:"crawler"`

		Attack struct {
			Timeout string `yaml:"timeout"`
			Backoff string `yaml:"backoff"`
			Threads int    `yaml:"threads"`
		} `yaml:"attack"`

		Triage struct {
			Threads int `yaml:"threads"`
		} `yaml:"triage"`

		Notifications struct {
			WebhookURL     string   `yaml:"webhook_url"`
			SendStatus     bool     `yaml:"send_status"`
			StatusInterval string   `yaml:"status_interval"`
			StatusAt       []string `yaml:"status_at"`
		} `yaml:"notifications"`

		UserAgent string `yaml:"agent"`
	}{}

	err := value.Decode(&custom_struct)
	if err != nil {
		return err
	}

	cfg.SubdomainFile = custom_struct.SubdomainFile

	cfg.Crawler.Timeout, _ = time.ParseDuration(custom_struct.Crawler.Timeout)
	cfg.Crawler.Backoff, _ = time.ParseDuration(custom_struct.Crawler.Backoff)
	cfg.Crawler.Threads = custom_struct.Crawler.Threads
	cfg.Crawler.TargetsPerSubdomain = custom_struct.Crawler.TargetsPerSubdomain
	cfg.Crawler.MinSubdomainAge, _ = time.ParseDuration(custom_struct.Crawler.MinSubdomainAge)

	cfg.Attack.Timeout, _ = time.ParseDuration(custom_struct.Attack.Timeout)
	cfg.Attack.Backoff, _ = time.ParseDuration(custom_struct.Attack.Backoff)
	cfg.Attack.Threads = custom_struct.Attack.Threads

	cfg.Triage.Threads = custom_struct.Triage.Threads

	cfg.Notifications.WebhookURL = custom_struct.Notifications.WebhookURL
	cfg.Notifications.SendStatus = custom_struct.Notifications.SendStatus
	cfg.Notifications.StatusInterval, _ = time.ParseDuration(custom_struct.Notifications.StatusInterval)
	cfg.Notifications.StatusAt = custom_struct.Notifications.StatusAt

	cfg.UserAgent = custom_struct.UserAgent

	for _, raw_regex := range custom_struct.Crawler.Regexes {
		cfg.Crawler.Regexes = append(cfg.Crawler.Regexes, regexp.MustCompile(raw_regex))
	}

	return nil
}

func ReadConfig(path string) *Config {

	file_content, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	cfg := Config{}

	err = yaml.Unmarshal(file_content, &cfg)
	if err != nil {
		panic(err)
	}

	return &cfg
}
