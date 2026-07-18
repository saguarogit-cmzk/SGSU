.PHONY: build test run

build:
	go build -trimpath -ldflags="-s -w" -o build/saguaro ./cmd/saguaro

test:
	go test ./...

run:
	SAGUARO_DATA_DIR=./var SAGUARO_SECURE_COOKIE=false SAGUARO_ADMIN_PASSWORD='change-this-development-password' go run ./cmd/saguaro
