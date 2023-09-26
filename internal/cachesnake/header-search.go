package cachesnake

import (
	"time"

	"github.com/valyala/fasthttp"
)

type HeaderBinarySearchArgs struct {
	Target                *AttackTarget
	NetCtx                *HttpContext
	UsePersistentHeaders  bool
	UseCookies            bool
	DisableNormalization  bool
	DisableSpecialHeaders bool
	HeaderValuePairs      [][]string
	ChunkSize             int
	Backoff               time.Duration
	DecisionFunc          func([][]string, *AttackTarget, *fasthttp.Response) Decision
}

func HeaderBinarySearch(args *HeaderBinarySearchArgs) [][]string {
	//Reset request & response object when we're done
	defer args.NetCtx.Request.Reset()
	defer args.NetCtx.Response.Reset()

	//start by splitting the list into chunk_size length chunks
	chunk_count := (len(args.HeaderValuePairs) / args.ChunkSize)

	main_header_list := make([][][]string, 0, chunk_count+1)

	for i := 0; i < chunk_count; i++ {
		main_header_list = append(main_header_list, args.HeaderValuePairs[(i*args.ChunkSize):((i*args.ChunkSize)+args.ChunkSize)])
	}

	last_chunk_len := (len(args.HeaderValuePairs) % args.ChunkSize)
	if last_chunk_len != 0 {
		chunk_count += 1
		main_header_list = append(main_header_list, args.HeaderValuePairs[len(args.HeaderValuePairs)-last_chunk_len:])
	}

	//Now, we have a list of chunk sized lists of pairs of headers & values, wheew!
	//We perform binary search on the header list now
	for {
		//loop over header sublists, see which ones aren't interesting, and delete them
		for i, header_sublist := range main_header_list {
			//Reset request & response objects
			args.NetCtx.Request.Reset()
			args.NetCtx.Response.Reset()

			//Setup the request URL & method
			args.NetCtx.Request.SetRequestURI(args.Target.TargetURL)
			args.NetCtx.Request.Header.SetMethod("GET")

			//Setup normalization & necessary headers
			if args.DisableNormalization {
				args.NetCtx.Request.Header.DisableNormalizing()
				defer args.NetCtx.Request.Header.EnableNormalizing()
			}

			if args.DisableSpecialHeaders {
				args.NetCtx.Request.Header.DisableSpecialHeader()
				defer args.NetCtx.Request.Header.EnableSpecialHeader()
				args.NetCtx.Request.UseHostHeader = true
				args.NetCtx.Request.Header.Set("Host", string(args.NetCtx.Request.Host()))
				args.NetCtx.Request.Header.Set("user-agent", args.NetCtx.Client.Name)
			}

			//Set URL params & cache buster headers
			cache_buster := GenRandString(10)
			query_params := args.NetCtx.Request.URI().QueryArgs()
			query_params.Add("cachebuster", cache_buster)

			args.NetCtx.Request.Header.Set("accept", "*/*, text/"+cache_buster)

			//Add persistent headers if any
			if args.UsePersistentHeaders {
				for _, h_v := range args.NetCtx.PersistentHeaders {
					args.NetCtx.Request.Header.Set(h_v[0], h_v[1])
				}
			}

			//Add cookies if any
			if args.UseCookies {
				for _, c_v := range args.NetCtx.Cookies {
					args.NetCtx.Request.Header.SetCookie(c_v[0], c_v[1])
				}
			}

			//Add the headers
			for _, h := range header_sublist {
				args.NetCtx.Request.Header.Set(h[0], h[1])
			}

			//Send the request
			err := args.NetCtx.Client.Do(args.NetCtx.Request, args.NetCtx.Response)
			if err != nil {
				continue
			}

			//Mark the values to be deleted as nil
			decision := args.DecisionFunc(header_sublist, args.Target, args.NetCtx.Response)
			if !decision.ShouldKeep {
				main_header_list[i] = nil
			}

			//Respect the backoff time or face the wrath of the rate-limiter
			time.Sleep(args.Backoff)
		}

		//remove nil & empty entries (empty entries occurr during the last split sometimes)
		main_list_len := len(main_header_list)
		for i := 0; i < main_list_len; i++ {
			if main_header_list[i] == nil || len(main_header_list[i]) == 0 {
				main_header_list = FastRemove(main_header_list, i)
				main_list_len -= 1
				i -= 1
			}
		}

		//if there are no entries left we leave
		if len(main_header_list) == 0 {
			return nil
		}

		//if all entries are of length 1 we have our result, merge into one list & return it
		all_len_one := true
		for _, v := range main_header_list {
			all_len_one = all_len_one && (len(v) == 1)

			if !all_len_one {
				break
			}
		}

		if all_len_one {
			result := make([][]string, 0, len(main_header_list))

			for _, v := range main_header_list {
				result = append(result, v[0])
			}

			return result
		}

		//otherwise, we split the sublists & try again
		new_main_header_list := make([][][]string, 0, len(main_header_list)*2)
		for _, header_sublist := range main_header_list {
			new_main_header_list = append(new_main_header_list, header_sublist[:len(header_sublist)/2])
			new_main_header_list = append(new_main_header_list, header_sublist[len(header_sublist)/2:])
		}
		main_header_list = new_main_header_list
	}
}

func IsHeaderEffectCached(args *HeaderBinarySearchArgs) []Decision {
	//Reset request & response object when we're done
	defer args.NetCtx.Request.Reset()
	defer args.NetCtx.Response.Reset()

	result := make([]Decision, len(args.HeaderValuePairs))

	//loop over all header-value pairs & determine if their effect is cached
	for i, h_v_pair := range args.HeaderValuePairs {
		//Reset request & response objects
		args.NetCtx.Request.Reset()
		args.NetCtx.Response.Reset()

		//Setup the request URL & method
		args.NetCtx.Request.SetRequestURI(args.Target.TargetURL)
		args.NetCtx.Request.Header.SetMethod("GET")

		//Setup normalization & necessary headers
		if args.DisableNormalization {
			args.NetCtx.Request.Header.DisableNormalizing()
			defer args.NetCtx.Request.Header.EnableNormalizing()
		}

		if args.DisableSpecialHeaders {
			args.NetCtx.Request.Header.DisableSpecialHeader()
			defer args.NetCtx.Request.Header.EnableSpecialHeader()
			args.NetCtx.Request.UseHostHeader = true
			args.NetCtx.Request.Header.Set("Host", string(args.NetCtx.Request.Host()))
			args.NetCtx.Request.Header.Set("user-agent", args.NetCtx.Client.Name)
		}

		//Set URL params & cache buster headers
		cache_buster := GenRandString(10)
		query_params := args.NetCtx.Request.URI().QueryArgs()
		query_params.Add("cachebuster", cache_buster)

		args.NetCtx.Request.Header.Set("accept", "*/*, text/"+cache_buster)

		//Add persistent headers if any
		if args.UsePersistentHeaders {
			for _, h_v := range args.NetCtx.PersistentHeaders {
				args.NetCtx.Request.Header.Set(h_v[0], h_v[1])
			}
		}

		//Add cookies if any
		if args.UseCookies {
			for _, c_v := range args.NetCtx.Cookies {
				args.NetCtx.Request.Header.SetCookie(c_v[0], c_v[1])
			}
		}

		//Set header to be tested
		args.NetCtx.Request.Header.Set(h_v_pair[0], h_v_pair[1])

		//Send the request with the header
		err := args.NetCtx.Client.Do(args.NetCtx.Request, args.NetCtx.Response)
		if err != nil {
			continue
		}

		//Note the result with the header present
		//Keep track of the reason of the decision
		result_with_header := args.DecisionFunc([][]string{h_v_pair}, args.Target, args.NetCtx.Response)

		//Remove tested header
		args.NetCtx.Request.Header.Del(h_v_pair[0])
		args.NetCtx.Request.Header.Set("Host", string(args.NetCtx.Request.Host()))
		args.NetCtx.Request.Header.Set("user-agent", args.NetCtx.Client.Name)

		//Resend the request without the header
		err = args.NetCtx.Client.Do(args.NetCtx.Request, args.NetCtx.Response)
		if err != nil {
			continue
		}

		//Note result without the header present
		result_without_header := args.DecisionFunc([][]string{h_v_pair}, args.Target, args.NetCtx.Response)

		//Control, make sure we didn't just get a captcha or something of the sort
		//If the decision tells us we should keep the result, it means it wasn't cache,
		//rather some defense mechanism, that changes the page for us only.
		//Cloudflare is the usual offender here.
		if !(result_with_header.ShouldKeep && result_without_header.ShouldKeep) {
			continue
		}

		cache_buster = GenRandString(10)
		query_params.Set("cachebuster", cache_buster)

		args.NetCtx.Request.Header.Set("accept", "*/*, text/"+cache_buster)

		err = args.NetCtx.Client.Do(args.NetCtx.Request, args.NetCtx.Response)
		if err != nil {
			continue
		}

		control_result := args.DecisionFunc([][]string{h_v_pair}, args.Target, args.NetCtx.Response)

		//The result is cached only if both tests are true
		result[i].ShouldKeep = !control_result.ShouldKeep
		result[i].Reasons = result_with_header.Reasons

		//Respect the backoff time or face the wrath of the rate-limiter
		time.Sleep(args.Backoff)
	}

	return result
}
