#!/bin/bash

GOPROTO="$(go list -f '{{ .Dir }}' -m github.com/golang/protobuf)"
protoc -I=${GOPROTO}/ptypes -I=. --gogo_out=plugins=grpc:. ./*.proto
