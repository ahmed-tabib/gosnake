module gosnakeauto

go 1.20

replace automation.com/cachesnake => ../../internal/cachesnake

require automation.com/cachesnake v0.0.0-00010101000000-000000000000

require (
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/klauspost/compress v1.16.3 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.48.0 // indirect
)
