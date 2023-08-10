package cachesnake

import (
	"time"

	"github.com/valyala/fasthttp"
)

func RunSpecificAttacks(t *Target, timeout time.Duration, backoff time.Duration) SpecificAttackResult {
	//Setup HTTP context
	net_ctx := HttpContext{}

	net_ctx.client = &fasthttp.Client{
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
		ReadTimeout:                   timeout,
		Name:                          "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0",
	}

	net_ctx.request = fasthttp.AcquireRequest()
	net_ctx.response = fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(net_ctx.request)
	defer fasthttp.ReleaseResponse(net_ctx.response)

	//Setting Up the result object
	result := SpecificAttackResult{
		t:            t,
		vulns:        make([]Vuln, 0, 10),
		time_started: time.Now(),
	}

	//Run the attacks & aggregate results
	//if t.cookie_search_only {

	//}

	//Note the time & return
	result.time_stopped = time.Now()
	return result
}

func RunPathOverride(t *Target, net_ctx *HttpContext, backoff time.Duration) (bool, []string) {
	//necessary boilerplate
	t.AcquireTarget(backoff)
	defer t.ReleaseTarget()
	defer t.MarkRequested()
	//clear the request and response objects, they will be reused by the next function
	defer net_ctx.request.Reset()
	defer net_ctx.response.Reset()

	is_vulnerable := false
	header_list := make([]string, 0, 2)

	//If not 200 there's nothing to do
	if t.initial_response.StatusCode() != 200 {
		return false, nil
	}

	return is_vulnerable, header_list
}
