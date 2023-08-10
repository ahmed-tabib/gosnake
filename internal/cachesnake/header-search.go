package cachesnake

import (
	"time"

	"github.com/valyala/fasthttp"
)

type HeaderBinarySearchArgs struct {
	t                      *Target
	net_ctx                *HttpContext
	use_persistent_headers bool
	persistent_headers     [][]string
	use_cookies            bool
	cookies                [][]string
	header_value_pairs     [][]string
	chunk_size             int
	backoff                time.Duration
	decision_func          func([][]string, *Target, *fasthttp.Response) bool
}

func HeaderBinarySearch(args *HeaderBinarySearchArgs) []string {
	//start by splitting the list into chunk_size length chunks
	chunk_count := (len(args.header_value_pairs) / args.chunk_size)

	main_header_list := make([][][]string, 0, chunk_count+1)

	for i := 0; i < chunk_count; i += args.chunk_size {
		main_header_list = append(main_header_list, args.header_value_pairs[i:i+args.chunk_size])
	}

	last_chunk_len := (len(args.header_value_pairs) % args.chunk_size)
	if last_chunk_len != 0 {
		chunk_count += 1
		main_header_list = append(main_header_list, args.header_value_pairs[len(args.header_value_pairs)-last_chunk_len:])
	}

	//define a temporary function we use to remove an element from a slice
	remove := func(s [][][]string, i int) [][][]string { s[len(s)-1], s[i] = nil, s[len(s)-1]; return s[:len(s)-1] }

	//Now, we have a list of chunk sized lists of pairs of headers & values, wheew!
	//We perform binary search on the header list now
	for {
		//loop over header sublists, see which ones aren't interesting, and delete them
		for i, header_sublist := range main_header_list {

			//Setup the request URL & method
			args.net_ctx.request.SetRequestURI(args.t.target_url)
			args.net_ctx.request.Header.SetMethod("GET")

			//Set URL params & cache buster headers
			cache_buster := GenRandString(10)
			query_params := args.net_ctx.request.URI().QueryArgs()
			query_params.Add("cachebuster", cache_buster)

			args.net_ctx.request.Header.Set("Accept", "*/*, text/"+cache_buster)

			//Add persistent headers if any
			if args.use_persistent_headers {
				for _, h_v := range args.persistent_headers {
					args.net_ctx.request.Header.Set(h_v[0], h_v[1])
				}
			}

			//Add cookies if any
			if args.use_cookies {
				for _, c_v := range args.cookies {
					args.net_ctx.request.Header.SetCookie(c_v[0], c_v[1])
				}
			}

			//Add the headers
			for _, h := range header_sublist {
				args.net_ctx.request.Header.Add(h[0], h[1])
			}

			//Send the request
			err := args.net_ctx.client.Do(args.net_ctx.request, args.net_ctx.response)
			if err != nil {
				args.net_ctx.request.Reset()
				args.net_ctx.response.Reset()
				continue
			}

			//Mark the values to be deleted as nil
			if !args.decision_func(header_sublist, args.t, args.net_ctx.response) {
				main_header_list[i] = nil
			}

			//Respect the backoff time or face the wrath of the rate-limiter
			time.Sleep(args.backoff)
		}

		//remove nil & empty entries (empty entries occurr during the last split sometimes)
		main_list_len := len(main_header_list)
		for i := 0; i < main_list_len; i++ {
			if main_header_list[i] == nil || len(main_header_list[i]) == 0 {
				main_header_list = remove(main_header_list, i)
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
			result := make([]string, 0, len(main_header_list))

			for _, v := range main_header_list {
				result = append(result, v[0][0])
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
