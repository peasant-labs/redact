module github.com/peasant-labs/redact

retract v0.1.0-rc1 // accidentally targeted a pre-module commit; use v0.1.0-rc2 or later

go 1.25.5

require (
	github.com/peasant-labs/schema v0.1.0-rc11
	github.com/tree-sitter/go-tree-sitter v0.25.0
	github.com/tree-sitter/tree-sitter-bash v0.25.1
	github.com/tree-sitter/tree-sitter-go v0.25.0
	github.com/tree-sitter/tree-sitter-javascript v0.25.0
	github.com/tree-sitter/tree-sitter-python v0.25.0
	github.com/tree-sitter/tree-sitter-typescript v0.23.2
	go.uber.org/goleak v1.3.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/dayvidpham/bestiary v0.2.9 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-pointer v0.0.1 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/santhosh-tekuri/jsonschema/v5 v5.3.1 // indirect
	github.com/swaggest/jsonschema-go v0.3.79 // indirect
	github.com/swaggest/refl v1.4.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	modernc.org/libc v1.55.3 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
	modernc.org/sqlite v1.33.1 // indirect
	zombiezen.com/go/sqlite v1.4.0 // indirect
)
