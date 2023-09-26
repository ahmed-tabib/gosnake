package cachesnake

import (
	"bytes"
	"container/list"
	"regexp"
	"strings"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/valyala/fasthttp"
)

func GenerateTargets(subdomain_list []*Subdomain, targets_per_subdomain int, timeout time.Duration, backoff time.Duration, useragent string, regex_list []*regexp.Regexp, out chan<- *AttackTarget) {
	// bloom filter for visited urls
	visited_urls := bloom.NewWithEstimates(uint(targets_per_subdomain*len(subdomain_list)), 0.02)

	for _, subdomain := range subdomain_list {
		url_queue := list.New()
		target_count := 2
		js_target_count := 0

		// some seed values to startup our search
		url_queue.PushBack("http://" + subdomain.Value)
		url_queue.PushBack("https://" + subdomain.Value)

		// As long as we have urls in our queue & the number of targets generated is below the limit, iterate.
		for url_queue.Len() > 0 && target_count <= targets_per_subdomain {
			// Pop the first element from the queue
			url, _ := url_queue.Remove(url_queue.Front()).(string)

			// verify the url is not already visited
			if visited_urls.TestString(url) {
				continue
			}

			// lock the subdomain
			subdomain.SubLock.Lock()

			// visit url
			time.Sleep(backoff)
			status_code, cookies, url_matches := urlVisitAndExtract(url, regex_list, timeout, useragent)
			visited_urls.AddString(url)

			if strings.HasSuffix(url, ".js") {
				js_target_count++
			}

			// add cookies to subdomain object
			for _, c := range cookies {
				already_in_list := false
				for _, s_c := range subdomain.CookieList {

					if bytes.Equal(s_c.Key(), c.Key()) {
						already_in_list = true
						break
					}

				}
				if !already_in_list {
					normalized_cookie_name := strings.ToLower(string(c.Key()))
					if !(strings.Contains(normalized_cookie_name, "session") || strings.Contains(normalized_cookie_name, "sess")) {
						c.SetValueBytes(append(c.Value(), []byte(GenRandString(8))...))
					}
					subdomain.CookieList = append(subdomain.CookieList, c)
				}
			}

			// release subdomain
			subdomain.SubLock.Unlock()

			// verify useful status code
			if status_code < 200 || status_code > 308 {
				continue
			}

			// submit url as a target
			target_count++
			out <- &AttackTarget{
				TargetURL:        url,
				ParentSubdomain:  subdomain,
				CookieSearchOnly: js_target_count > 3,
			}

			// loop over urls found in the page
			if len(url_matches) == 0 {
				continue
			}

			for _, match_list := range url_matches {
				for _, match := range match_list {

					// prepare the url
					if strings.HasPrefix(match, "//") {

						match, _ = strings.CutPrefix(match, "//")
						match = "https://" + match

					} else if strings.HasPrefix(match, "/") {

						protocol_url_pair := strings.Split(url, "://")
						root_url := protocol_url_pair[0] + "://" + strings.Split(protocol_url_pair[1], "/")[0]
						match = root_url + match

					} else if !strings.HasPrefix(match, "http://") && !strings.HasPrefix(match, "https://") {
						// ignore url fragments & params etc...
						continue
					}

					// Remove fragments & params
					match = strings.Split(strings.Split(match, "?")[0], "#")[0]

					// Check if we already visited the url
					if visited_urls.TestString(match) {
						continue
					}

					// Add url to queue if in scope
					host := strings.Split(strings.Split(match, "://")[1], "/")[0]
					if subdomain.ParentProgram.IsInScope(host) {
						url_queue.PushBack(match)
					}

				}
			}
		}
	}
}

// visit url, extract cookies & urls
func urlVisitAndExtract(url string, regex_list []*regexp.Regexp, timeout time.Duration, useragent string) (int, []*fasthttp.Cookie, [][]string) {
	// Get request & response objects
	request := fasthttp.AcquireRequest()
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)

	// Setup request
	request.SetRequestURI(url)
	request.Header.SetMethod("GET")
	request.Header.SetUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0")

	// Send request
	err := fasthttp.DoTimeout(request, response, timeout)
	if err != nil {
		return 0, nil, nil
	}

	status_code := response.StatusCode()
	cookies := make([]*fasthttp.Cookie, 0, 4)

	// extract cookies
	response.Header.VisitAllCookie(func(_ []byte, value []byte) {
		c := &fasthttp.Cookie{}
		c.ParseBytes(value)
		cookies = append(cookies, c)
	})

	if len(cookies) == 0 {
		cookies = nil
	}

	// Process depending on the status code
	if status_code == 200 {
		body := response.Body()

		match_list := make([][]string, 0, len(regex_list))

		for _, regex := range regex_list {
			full_matches := regex.FindAllSubmatch(body, -1)
			match_sublist := make([]string, 0, len(full_matches))

			for _, match := range full_matches {
				match_sublist = append(match_sublist, string(match[1]))
			}

			match_list = append(match_list, match_sublist)
		}

		if len(match_list) == 0 {
			match_list = nil
		}

		return status_code, cookies, match_list
	} else if status_code >= 301 && status_code <= 308 {
		match_list := [][]string{{string(response.Header.Peek("location"))}}

		return status_code, cookies, match_list
	} else {
		return status_code, cookies, nil
	}

}
