# GoSnake - Web Cache Misconfiguration Scanner

GoSnake is an open-source security tool written in Go, containing two binaries designed to identify and detect web cache misconfigurations. The project consists of:

1. **Command Line Tool**: A work-in-progress command-line tool that scans web applications for cache misconfigurations.
  
2. **Automation Tool**: An automation tool that utilizes a Discord webhook and MongoDB to send notifications of vulns found during the scanning of specified subdomains.

## Features

- **Web Cache Misconfiguration Detection**: Scans web applications for common misconfigurations related to caching mechanisms.
  
- **User-Friendly Output**: Provides clear and concise output, making it easy for users to understand and address identified issues.

- **Discord Webhook Notifications**: Pushes notifications of found vulnerabilities, status & other info using discord webhooks

- **Customizable Scan and Notify Options**: Users can specify a configuration file to customize scan parameters.

## Getting Started

### Prerequisites

- Go (version 1.21.0 or higher)

### Installation
```bash
go get -u github.com/ahmed-tabib/gosnake/cmd/gosnake-cli
go get -u github.com/ahmed-tabib/gosnake/cmd/gosnake-auto
```

## Usage

### Command Line Tool
```bash
gosanke-cli -c=config.yaml
```
### Automation Tool
```bash
gosnake-auto -c=config.yaml
```

## Configuration File

Create a YAML configuration file (e.g., `config.yaml`) to specify scan parameters for both tools:

```yaml

agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"

mongo:
  uri:                  "localhost:27701"
  db_name:              "bug-bounty"
  subdomain_collection: "subdomains"
  program_collection:   "programs"
  vuln_collection:      "vulns"

crawler:
  timeout: 10s
  backoff: 1000ms
  threads: 20
  regexes: 
    - "<script[^>]*src=[\"']?([^\\?#'\" ]*)[\\?#\"']?"
    - "<a[^>]*href=[\"']?([^\\?#'\" ]*)[\\?#\"']?"
  targets_per_subdomain: 20
  min_subdomain_age: 24h

attack:
  timeout: 10s
  backoff: 1000ms
  threads: 300

triage:
  threads: 5


notifications:
  webhook_url: "https://discord.com/api/webhooks/xxxxxxxxxxxxxxxxxxxxxxxxx"
  send_status: true
  status_interval: 0
  status_at:
    - "06:30:00"

```

## Example Notification

```
----------[VULN REPORT]----------
[Current Time]: 2023-09-27T09:49:19Z
[Attack Started]: 2023-09-27T09:46:28Z
[Attack Stopped]: 2023-09-27T09:49:19Z
[Time Elapsed]: 2m51.001s

[Program Info]: 
    Name:         N/A
    Platform:     N/A
    Program URL:  N/A
    Has Bounties: false

[Target Info]: 
    Subdomain: www.redacted.com
    URL: "https://www.redacted.com/cachexrnxu.css"

[Vulns Found]: 1

[Vuln 1]: 
    Name:    Reflected Cookie
    Details: Cookie value reflected in response. Cached. 
    Headers: 
        "HMS=eb0bfcb3-24ad-405e-b3cd-aae1b7096571gjsayjfw; max-age=1800; domain=.redacted.com; path=/; secure; SameSite=None"
    Impact: [XSS ATO]
    Found At: 2023-09-27T09:46:29Z

```

## Contributing

We welcome contributions from the community! If you find a bug, have a feature request, or would like to contribute code, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

- [fasthttp](https://github.com/valyala/fasthttp) - A fast HTTP implementation for Go
- [MongoDB Go Driver](https://github.com/mongodb/mongo-go-driver)
