#!/bin/sh

shopt -s globstar

protoc --go_out=../pb --go_opt=module=xorkevin.dev/bitcensus/pb **/*.proto
