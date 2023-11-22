OUTPUT=output
APP ?=crypto-cli

PROJECT=go-crypto
LDFLAGS += -X "$(PROJECT)/version.BuildTS=$(shell TZ='Asia/Shanghai' date '+%Y-%m-%d %I:%M:%S')"
LDFLAGS += -X "$(PROJECT)/version.GitHash=$(shell git rev-parse HEAD)"
LDFLAGS += -X "$(PROJECT)/version.GitBranch=$(shell git rev-parse --abbrev-ref HEAD)"
LDFLAGS += -X "$(PROJECT)/version.App=$(APP)"

build: clean output
	go build -ldflags '$(LDFLAGS)' -o $(OUTPUT)/$(APP) crypto-cli/main.go

clean:
	rm -rf $(OUTPUT)

output:
	mkdir -p $(OUTPUT)

.PHNOY: clean output build