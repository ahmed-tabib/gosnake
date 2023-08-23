package cachesnake

import (
	"strings"

	"github.com/valyala/fasthttp"
)

const (
	reason_None                 = 0
	reason_StatusCodeModified   = 1
	reason_ValueReflectedHeader = 2
	reason_ValueReflectedBody   = 3
	reason_SetCookiePresent     = 4
	reason_MethodModified       = 5
)

type Decision struct {
	ShouldKeep bool
	Reasons    []int
}

// keep the header if the status code was modified
func DecisionFuncStatusCodeModified(_ [][]string, target *AttackTarget, response *fasthttp.Response) Decision {
	shouldKeep := response.StatusCode() != target.InitialResponse.StatusCode()

	if shouldKeep {
		return Decision{true, []int{reason_StatusCodeModified}}
	}

	return Decision{false, nil}
}

// keep the header if the status code is changed to a redirect
func DecisionFuncStatusCodeRedirect(_ [][]string, target *AttackTarget, response *fasthttp.Response) Decision {
	shouldKeep := (response.StatusCode() != target.InitialResponse.StatusCode()) && (response.StatusCode() >= 301 && response.StatusCode() <= 308)

	if shouldKeep {
		return Decision{true, []int{reason_StatusCodeModified}}
	}

	return Decision{false, nil}
}

// keep the header if the body becomes really small (HEAD response)
func DecisionFuncSmallBody(_ [][]string, target *AttackTarget, response *fasthttp.Response) Decision {
	shouldKeep := len(response.Body()) <= 2 && len(target.InitialResponse.Body()) > 2

	if shouldKeep {
		return Decision{true, []int{reason_MethodModified}}
	}

	return Decision{false, nil}
}

// keep the header if the location response header contains a reflected value
func DecisionFuncLocationHeader(header_value_pairs [][]string, _ *AttackTarget, response *fasthttp.Response) Decision {
	if len(header_value_pairs) == 0 {
		return Decision{false, nil}
	}

	if response.StatusCode() > 308 || response.StatusCode() < 301 {
		return Decision{false, nil}
	}

	response.Header.EnableNormalizing()

	if strings.Contains(string(response.Header.Peek("location")), header_value_pairs[0][1]) {
		return Decision{true, []int{reason_ValueReflectedHeader}}
	}

	return Decision{false, nil}
}

// keep the header if it causes a host override
func DecisionFuncHostOverride(header_value_pairs [][]string, target *AttackTarget, response *fasthttp.Response) Decision {
	if len(header_value_pairs) == 0 {
		return Decision{false, nil}
	}

	reasons := make([]int, 0, 2)
	shouldKeep := false

	if target.InitialResponse.StatusCode() != response.StatusCode() {
		reasons = append(reasons, reason_StatusCodeModified)
		shouldKeep = true
	}
	if strings.Contains(string(response.Body()), header_value_pairs[0][1]) {
		reasons = append(reasons, reason_ValueReflectedBody)
		shouldKeep = true
	}

	if shouldKeep {
		return Decision{true, reasons}
	} else {
		return Decision{false, nil}
	}
}

func DecisionFuncPortDos(header_value_pairs [][]string, target *AttackTarget, response *fasthttp.Response) Decision {
	d1 := DecisionFuncLocationHeader(header_value_pairs, target, response)
	d2 := DecisionFuncHostOverride(header_value_pairs, target, response)

	if d1.ShouldKeep || d2.ShouldKeep {
		return Decision{true, append(d1.Reasons, d2.Reasons...)}
	} else {
		return Decision{false, nil}
	}
}

// keep the header for one of a multitude of reasons. use for bruteforce
func DecisionFuncBruteforce(header_value_pairs [][]string, target *AttackTarget, response *fasthttp.Response) Decision {
	if len(header_value_pairs) == 0 {
		return Decision{false, nil}
	}

	reasons := make([]int, 0, 2)
	shouldKeep := false

	if target.InitialResponse.StatusCode() != response.StatusCode() {
		reasons = append(reasons, reason_StatusCodeModified)
		shouldKeep = true
	}

	if strings.Contains(string(response.Body()), "wcpcanary007") {
		reasons = append(reasons, reason_ValueReflectedBody)
		shouldKeep = true
	}

	// response.Header.EnableNormalizing()
	// if len(response.Header.Peek("Set-Cookie")) > 0 {
	// 	reasons = append(reasons, reason_SetCookiePresent)
	// 	shouldKeep = true
	// }

	if shouldKeep {
		return Decision{true, reasons}
	} else {
		return Decision{false, nil}
	}
}
