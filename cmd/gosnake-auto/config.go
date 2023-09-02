package main

import (
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Mongo struct {
		URI               string
		DBName            string
		SubdomainCollName string
		ProgramCollName   string
		VulnCollName      string
	}

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
		Mongo struct {
			URI               string `yaml:"uri"`
			DBName            string `yaml:"db_name"`
			SubdomainCollName string `yaml:"subdomain_collection"`
			ProgramCollName   string `yaml:"program_collection"`
			VulnCollName      string `yaml:"vuln_collection"`
		} `yaml:"mongo"`

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

	cfg.Mongo.URI = custom_struct.Mongo.URI
	cfg.Mongo.DBName = custom_struct.Mongo.DBName
	cfg.Mongo.SubdomainCollName = custom_struct.Mongo.SubdomainCollName
	cfg.Mongo.ProgramCollName = custom_struct.Mongo.ProgramCollName
	cfg.Mongo.VulnCollName = custom_struct.Mongo.VulnCollName

	cfg.Crawler.Timeout, _ = time.ParseDuration(custom_struct.Crawler.Timeout)
	cfg.Crawler.Backoff, _ = time.ParseDuration(custom_struct.Crawler.Backoff)
	cfg.Crawler.Threads = custom_struct.Crawler.Threads
	cfg.Crawler.TargetsPerSubdomain = custom_struct.Crawler.TargetsPerSubdomain
	cfg.Crawler.MinSubdomainAge, _ = time.ParseDuration(custom_struct.Crawler.MinSubdomainAge)

	cfg.Attack.Timeout, _ = time.ParseDuration(custom_struct.Attack.Timeout)
	cfg.Attack.Backoff, _ = time.ParseDuration(custom_struct.Attack.Backoff)
	cfg.Attack.Threads = custom_struct.Attack.Threads

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
