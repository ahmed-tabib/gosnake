package cachesnake

import (
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

// Carries the client, response, & request objects to be reused
// easier to pass to functions than each individually
type HttpContext struct {
	client   *fasthttp.Client
	request  *fasthttp.Request
	response *fasthttp.Response
}

type Vuln struct {
	name              string
	offending_headers []string
	impact            []string
}

type SpecificAttackResult struct {
	t            *Target
	vulns        []Vuln
	time_started time.Time
	time_stopped time.Time
}

type BBProgram struct {
	program_name    string
	program_url     string
	offers_bounties bool
	in_scope        []string
	out_of_scope    []string
}

type Subdomain struct {
	value          string
	parent_program *BBProgram
	last_requested time.Time
	sub_lock       sync.Mutex
}

type Target struct {
	target_url         string
	initial_response   *fasthttp.Response
	parent_subdomain   *Subdomain
	cookie_search_only bool
}

// This function is meant to enforce a backoff time between requests
// to the same subdomain. Different targets belonging to the same
// subdomain maybe tested simultaneously, which is why this function
// MUST be called before initiating any requests to a target.
// The lock is at the level of the subdomain. rate-limit is a bitch
func (t *Target) AcquireTarget(backoff time.Duration) {

	t.parent_subdomain.sub_lock.Lock()
	duration := time.Since(t.parent_subdomain.last_requested)

	if duration < backoff {
		time.Sleep(backoff - duration)
	}
}

// Once we're done sending requests to the target, we release it.
func (t *Target) ReleaseTarget() {
	t.parent_subdomain.sub_lock.Unlock()
}

// Just to update the last_requested
func (t *Target) MarkRequested() {
	t.parent_subdomain.last_requested = time.Now()
}
