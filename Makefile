BINARY_NAME=recon-tool
VERSION=1.0.0

.PHONY: build clean install release

build:
	go build -o $(BINARY_NAME) .

build-all:
	GOOS=linux GOARCH=amd64 go build -o releases/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -o releases/$(BINARY_NAME)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 go build -o releases/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -o releases/$(BINARY_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -o releases/$(BINARY_NAME)-windows-amd64.exe .

clean:
	rm -f $(BINARY_NAME)
	rm -rf releases/

install: build
	sudo mv $(BINARY_NAME) /usr/local/bin/

release: clean
	mkdir -p releases
	$(MAKE) build-all