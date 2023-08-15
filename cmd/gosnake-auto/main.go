package main

import (
	"fmt"
	"time"

	"automation.com/cachesnake"
	"github.com/valyala/fasthttp"
)

func printResult(r cachesnake.AttackResult) {
	fmt.Println("---------------VULN REPORT-----------------")

	fmt.Println("Time started:", r.TimeStarted)
	fmt.Println("Time stopped:", r.TimeStopped)

	if len(r.VulnList) == 0 {
		fmt.Println("No vulnerabilities found.")
	}

	for i, v := range r.VulnList {
		fmt.Println("--- Vuln", i+1, "---")
		fmt.Println("Vuln found through: ", v.Name)
		fmt.Println("Details: ", v.Details)
		fmt.Println("Assessed Impact: ", v.Impact)
		fmt.Println("Problem In: \"", v.OffendingHeaders, "\"")
		fmt.Println("Found on: ", v.TimeFound)
	}

}

func main() {

	bbprogram := cachesnake.BBProgram{}
	subdomain := cachesnake.Subdomain{
		Value:         "0abf0046039442db8188b64200440024.web-security-academy.net",
		ParentProgram: &bbprogram,
		CookieList:    make([]*fasthttp.Cookie, 0),
	}
	target := cachesnake.AttackTarget{
		TargetURL:       "https://0abf0046039442db8188b64200440024.web-security-academy.net/",
		InitialResponse: fasthttp.AcquireResponse(),
		ParentSubdomain: &subdomain,
	}

	//Setup HTTP context
	net_ctx := cachesnake.HttpContext{PersistentHeaders: make([][]string, 0)}

	net_ctx.Client = &fasthttp.Client{
		DisableHeaderNamesNormalizing: false,
		DisablePathNormalizing:        true,
		ReadTimeout:                   15 * time.Second,
		Name:                          "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0",
	}

	net_ctx.Request = fasthttp.AcquireRequest()
	net_ctx.Response = fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(net_ctx.Request)
	defer fasthttp.ReleaseResponse(net_ctx.Response)

	net_ctx.Request.SetRequestURI(target.TargetURL)
	net_ctx.Request.Header.SetMethod("GET")

	err := net_ctx.Client.Do(net_ctx.Request, net_ctx.Response)
	if err != nil {
		fmt.Println("Could not send first request: ", err)
		return
	}

	fmt.Println("First request status code: ", net_ctx.Response.StatusCode())

	net_ctx.Response.Header.VisitAllCookie(func(key []byte, value []byte) {
		cookie := fasthttp.AcquireCookie()
		cookie.ParseBytes(value)
		subdomain.CookieList = append(subdomain.CookieList, cookie)
		fmt.Println("Found cookie: ", cookie.String())
	})

	net_ctx.Response.CopyTo(target.InitialResponse)

	net_ctx.Response.Reset()
	net_ctx.Request.Reset()

	result := cachesnake.RunAttacks(&target, 15*time.Second, 1*time.Second)

	printResult(result)

}
