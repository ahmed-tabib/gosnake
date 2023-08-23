package main

import (
	"regexp"
	"time"
)

type Config struct {
	MongoURI               string
	MongoDBName            string
	MongoSubdomainCollName string
	MongoProgramCollName   string
	MongoVulnCollName      string

	CrawlerTimeout time.Duration
	CrawlerBackoff time.Duration

	AttackTimeout time.Duration
	AttackBackoff time.Duration

	UserAgent string

	SubdomainFetchThreads int
	TargetFetchThreads    int
	AttackThreads         int

	TargetsPerSubdomain int
	TargetFetchRegexes  []*regexp.Regexp
}
