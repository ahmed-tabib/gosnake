package cachesnake

import (
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

// Carries the client, response, & request objects to be reused
// easier to pass to functions than each individually
type HttpContext struct {
	Client            *fasthttp.Client
	Request           *fasthttp.Request
	Response          *fasthttp.Response
	PersistentHeaders [][]string
	Cookies           [][]string
}

type Vuln struct {
	Name             string
	Details          string
	OffendingHeaders []string
	Impact           []string
	TimeFound        time.Time
}

type AttackResult struct {
	Target      *AttackTarget
	VulnList    []Vuln
	TimeStarted time.Time
	TimeStopped time.Time
}

type HeaderBruteforceResult struct {
	OffendingHeader  string
	Reasons          []int
	IsCached         bool
	IsCacheable      bool
	CacheablePostfix string
}

type BBProgram struct {
	ProgramName    string
	ProgramURL     string
	Platform       string
	OffersBounties bool
	InScope        []string
	OutOfScope     []string
}

type Subdomain struct {
	Value         string
	ParentProgram *BBProgram
	LastRequested time.Time
	SubLock       sync.Mutex
}

type AttackTarget struct {
	TargetURL        string
	InitialResponse  *fasthttp.Response
	ParentSubdomain  *Subdomain
	CookieSearchOnly bool
}

// This function is meant to enforce a backoff time between requests
// to the same subdomain. Different targets belonging to the same
// subdomain maybe tested simultaneously, which is why this function
// MUST be called before initiating any requests to a target.
// The lock is at the level of the subdomain. rate-limit is a bitch
func (target *AttackTarget) AcquireTarget(backoff time.Duration) {

	target.ParentSubdomain.SubLock.Lock()
	duration := time.Since(target.ParentSubdomain.LastRequested)

	if duration < backoff {
		time.Sleep(backoff - duration)
	}
}

// Once we're done sending requests to the target, we release it.
func (target *AttackTarget) ReleaseTarget() {
	target.ParentSubdomain.SubLock.Unlock()
}

// Just to update the last_requested
func (target *AttackTarget) MarkRequested() {
	target.ParentSubdomain.LastRequested = time.Now()
}
