PROJDIR=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

# change to project dir so we can express all as relative paths
$(shell cd $(PROJDIR))

APP_NAME=check-password-strength

LD_FLAGS="-w -s"

$(shell mkdir -p tools/bin )

.PHONY: all
all: build

.PHONY: build
build: assets
	go build -ldflags $(LD_FLAGS) -o $(APP_NAME)

.PHONY: linux-64
linux-64: assets
	GOOS=linux GOARCH=amd64 go build -ldflags $(LD_FLAGS) -o $(APP_NAME)

.PHONY: macos-64
macos-64: assets
	GOOS=darwin GOARCH=amd64 go build -ldflags $(LD_FLAGS) -o $(APP_NAME)

.PHONY: windows-64
windows-64: assets
	GOOS=windows GOARCH=amd64 go build -ldflags $(LD_FLAGS) -o $(APP_NAME).exe

.PHONY: windows-32
windows-32: assets
	GOOS=windows GOARCH=386 go build -ldflags $(LD_FLAGS) -o $(APP_NAME).exe

.PHONY: assets
assets: go-bindata
	$(PROJDIR)/tools/bin/go-bindata -o assets/bindata.go -pkg assets assets/data/

.PHONY: go-bindata
go-bindata:
	GOBIN=$(PROJDIR)/tools/bin go install github.com/go-bindata/go-bindata/go-bindata@latest

.PHONY: test
test:
	go test -v -count 1 $(APP_NAME)/cmd

.PHONY: docker
docker:
	docker build -t $(APP_NAME) .

.PHONY: clean
clean:
	$(RM) $(APP_NAME) $(APP_NAME).exe

