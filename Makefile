.PHONY: build test run

build:
	go build -o fortify-sca-mcp .

test:
	go test ./...

run:
	go run .
