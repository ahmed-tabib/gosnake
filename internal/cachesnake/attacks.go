package cachesnake

import (
	"time"

	"github.com/valyala/fasthttp"
)

func RunSpecificAttacks(target *AttackTarget, timeout time.Duration, backoff time.Duration) SpecificAttackResult {
	//Setup HTTP context
	net_ctx := HttpContext{}

	net_ctx.Client = &fasthttp.Client{
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
		ReadTimeout:                   timeout,
		Name:                          "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0",
	}

	net_ctx.Request = fasthttp.AcquireRequest()
	net_ctx.Response = fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(net_ctx.Request)
	defer fasthttp.ReleaseResponse(net_ctx.Response)

	//Setting Up the result object
	result := SpecificAttackResult{
		Target:      target,
		VulnList:    make([]Vuln, 0, 10),
		TimeStarted: time.Now(),
	}

	//Run the attacks & aggregate results
	//if t.cookie_search_only {

	//}

	//Note the time & return
	result.TimeStopped = time.Now()
	return result
}

// Path override associated decision function
func pathOverrideDecisionFunc(_ [][]string, target *AttackTarget, response *fasthttp.Response) bool {
	return response.StatusCode() != target.InitialResponse.StatusCode()
}

// Attempt to cause a redirect through headers
// Main Impact: DoS, Inappropriate Content displayed.
func RunPathOverride(target *AttackTarget, net_ctx *HttpContext, backoff time.Duration) (bool, []string) {
	//necessary boilerplate
	target.AcquireTarget(backoff)
	defer target.ReleaseTarget()
	defer target.MarkRequested()
	//clear the request and response objects, they will be reused by the next function
	defer net_ctx.Request.Reset()
	defer net_ctx.Response.Reset()

	//If not 200 there's nothing to do
	if target.InitialResponse.StatusCode() != 200 {
		return false, nil
	}

	//Prepare headers & header bin search args
	header_value_pairs := make([][]string, len(PathOverrideHeaders))
	for i := range header_value_pairs {
		header_value_pairs[i] = []string{PathOverrideHeaders[i], "/404doesntexist"}
	}

	args := HeaderBinarySearchArgs{
		Target:               target,
		NetCtx:               net_ctx,
		UsePersistentHeaders: true,
		UseCookies:           false,
		HeaderValuePairs:     header_value_pairs,
		ChunkSize:            40,
		Backoff:              backoff,
		DecisionFunc:         pathOverrideDecisionFunc,
	}

	//Run Binary search on Headers
	bin_search_result := HeaderBinarySearch(&args)

	if len(bin_search_result) == 0 {
		return false, nil
	}

	//See if any results are cached
	args.HeaderValuePairs = bin_search_result
	cache_test_result := IsHeaderEffectCached(&args)

	result := make([]string, 0, len(bin_search_result))

	for i, v := range cache_test_result {
		if v {
			result = append(result, bin_search_result[i][0])
		}
	}

	if len(result) == 0 {
		return false, nil
	} else {
		return true, result
	}
}

func RunCookieSearch() {

}
