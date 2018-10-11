#!/usr/bin/env bash
go get -u github.com/pkg/errors
go get -u github.com/PuerkitoBio/goquery
go build cspparse.go
mv cspparse $GOPATH/bin
