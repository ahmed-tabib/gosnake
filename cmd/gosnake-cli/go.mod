module gosnakecli

go 1.20

replace automation.com/cachesnake => ../../internal/cachesnake

require (
	automation.com/cachesnake v0.0.0-00010101000000-000000000000
	github.com/valyala/fasthttp v1.48.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/bits-and-blooms/bitset v1.8.0 // indirect
	github.com/bits-and-blooms/bloom/v3 v3.5.0 // indirect
	github.com/klauspost/compress v1.16.3 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
)
