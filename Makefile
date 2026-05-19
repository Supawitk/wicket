.PHONY: build test test-race lint bench tidy clean

BINARY := bin/wicket

build:
	@mkdir -p bin
	go build -o $(BINARY) ./cmd/wicket

test:
	go test ./...

test-race:
	go test -race ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint not installed; skipping"; exit 0; \
	}
	golangci-lint run ./...

bench:
	go test -bench=. -benchmem ./...

tidy:
	go mod tidy

clean:
	rm -rf bin coverage.out coverage.html
