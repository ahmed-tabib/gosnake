package main

import (
	"fmt"
	"time"

	"automation.com/cachesnake"
	"github.com/valyala/fasthttp"
)

func main() {
	sub := cachesnake.Subdomain{
		Value:         "www.google.com",
		LastRequested: time.Now(),
	}

	client := &fasthttp.Client{}
	req := fasthttp.AcquireRequest()
	init_resp := fasthttp.AcquireResponse()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(init_resp)
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethod("GET")
	req.Header.SetRequestURI("https://www.google.com")

	err := client.Do(req, init_resp)
	if err != nil {
		return
	}

	t := cachesnake.AttackTarget{
		TargetURL:        "https://www.google.com/",
		InitialResponse:  init_resp,
		ParentSubdomain:  &sub,
		CookieSearchOnly: false,
	}

	net_ctx := cachesnake.HttpContext{Client: client, Request: req, Response: resp}
	h_v_pairs := [][]string{{"x-normal1\\", "val"}, {"x-normal2\\", "val"}, {"x-normal3", "val"}, {"x-normal4", "val"}, {"]nope]", "val"}, {"x-normal5", "val"}, {"x-normal6", "val"}, {"x-normal7", "val"}, {"x-normal8", "val"}, {"x-normal9", "val"}, {"x-normal10", "val"}}
	decision_func := func(h_v [][]string, target *cachesnake.AttackTarget, response *fasthttp.Response) bool {
		fmt.Println(response.StatusCode(), target.InitialResponse.StatusCode(), response.StatusCode() != target.InitialResponse.StatusCode())
		return response.StatusCode() != target.InitialResponse.StatusCode()
	}

	a := cachesnake.HeaderBinarySearchArgs{
		Target:               &t,
		NetCtx:               &net_ctx,
		UsePersistentHeaders: false,
		UseCookies:           false,
		HeaderValuePairs:     h_v_pairs,
		ChunkSize:            3,
		Backoff:              time.Second,
		DecisionFunc:         decision_func,
	}
	s := cachesnake.HeaderBinarySearch(&a)

	fmt.Println(s)
}
