package cachesnake

import (
	"time"

	"github.com/valyala/fasthttp"
)

type HeaderBinarySearchArgs struct {
	Target               *AttackTarget
	NetCtx               *HttpContext
	UsePersistentHeaders bool
	PersistentHeaders    [][]string
	UseCookies           bool
	Cookies              [][]string
	HeaderValuePairs     [][]string
	ChunkSize            int
	Backoff              time.Duration
	DecisionFunc         func([][]string, *AttackTarget, *fasthttp.Response) bool
}

func HeaderBinarySearch(args *HeaderBinarySearchArgs) []string {
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

	//define a temporary function we use to remove an element from a slice
	remove := func(s [][][]string, i int) [][][]string { s[len(s)-1], s[i] = nil, s[len(s)-1]; return s[:len(s)-1] }

	//Now, we have a list of chunk sized lists of pairs of headers & values, wheew!
	//We perform binary search on the header list now
	for {
		//loop over header sublists, see which ones aren't interesting, and delete them
		for i, header_sublist := range main_header_list {

			//Setup the request URL & method
			args.NetCtx.Request.SetRequestURI(args.Target.TargetURL)
			args.NetCtx.Request.Header.SetMethod("GET")

			//Set URL params & cache buster headers
			cache_buster := GenRandString(10)
			query_params := args.NetCtx.Request.URI().QueryArgs()
			query_params.Add("cachebuster", cache_buster)

			args.NetCtx.Request.Header.Set("Accept", "*/*, text/"+cache_buster)

			//Add persistent headers if any
			if args.UsePersistentHeaders {
				for _, h_v := range args.PersistentHeaders {
					args.NetCtx.Request.Header.Set(h_v[0], h_v[1])
				}
			}

			//Add cookies if any
			if args.UseCookies {
				for _, c_v := range args.Cookies {
					args.NetCtx.Request.Header.SetCookie(c_v[0], c_v[1])
				}
			}

			//Add the headers
			for _, h := range header_sublist {
				args.NetCtx.Request.Header.Add(h[0], h[1])
			}

			//Send the request
			err := args.NetCtx.Client.Do(args.NetCtx.Request, args.NetCtx.Response)
			if err != nil {
				args.NetCtx.Request.Reset()
				args.NetCtx.Response.Reset()
				continue
			}

			//Mark the values to be deleted as nil
			if !args.DecisionFunc(header_sublist, args.Target, args.NetCtx.Response) {
				main_header_list[i] = nil
			}

			//Reset request & response objects
			args.NetCtx.Request.Reset()
			args.NetCtx.Response.Reset()
			//Respect the backoff time or face the wrath of the rate-limiter
			time.Sleep(args.Backoff)
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
