.PHONY: all build image

all: build image


build:
	GOOS=linux go build -o ./cmd/calico-vpp-agent ./cmd


image: build
	docker build -t calicovpp/node:latest .
