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
	}

	Attack struct {
		Timeout time.Duration
		Backoff time.Duration
		Threads int
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
			Timeout             int      `yaml:"timeout"`
			Backoff             int      `yaml:"backoff"`
			Threads             int      `yaml:"threads"`
			Regexes             []string `yaml:"regexes"`
			TargetsPerSubdomain int      `yaml:"targets_per_subdomain"`
		} `yaml:"crawler"`

		Attack struct {
			Timeout int `yaml:"timeout"`
			Backoff int `yaml:"backoff"`
			Threads int `yaml:"threads"`
		} `yaml:"attack"`

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

	cfg.Crawler.Timeout = time.Duration(custom_struct.Crawler.Timeout) * time.Second
	cfg.Crawler.Backoff = time.Duration(custom_struct.Crawler.Backoff) * time.Second
	cfg.Crawler.Threads = custom_struct.Crawler.Threads
	cfg.Crawler.TargetsPerSubdomain = custom_struct.Crawler.TargetsPerSubdomain

	cfg.Attack.Timeout = time.Duration(custom_struct.Attack.Timeout) * time.Second
	cfg.Attack.Backoff = time.Duration(custom_struct.Attack.Backoff) * time.Second
	cfg.Attack.Threads = custom_struct.Attack.Threads

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
