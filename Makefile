GOCMD := go
GOBUILD := $(GOCMD) build
GOGENERATE := $(GOCMD) generate
GOCLEAN := $(GOCMD) clean

GO_BINARY := gonapt
GO_SOURCE := main.go
AUTO_GEN := naptprog_*

all: bpf_build build

bpf_build:
	$(GOGENERATE)

build:
	$(GOBUILD) -v .

clean:
	$(GOCLEAN)
	rm $(AUTO_GEN)
	sudo rm -rf /sys/fs/bpf/napt
