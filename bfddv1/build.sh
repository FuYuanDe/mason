#!/bin/sh
export PATH=$PATH:/usr/local/go/bin:/opt/s805-toolchains/bin
export GOPATH=`pwd`/../..
export GOROOT=/usr/local/go
CC=arm-linux-gnueabihf-gcc GOARCH=arm GOARM=7 CGO_ENABLED=1 /usr/local/go/bin/go build -ldflags="-w -s"