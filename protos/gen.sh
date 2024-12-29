#!/bin/sh

shopt -s globstar

protoc --go_out=../pb --go_opt=default_api_level=API_OPAQUE --go_opt=module=xorkevin.dev/bitcensus/pb **/*.proto
