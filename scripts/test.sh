#!/bin/bash
set -e

cd $(dirname $0)/..

# Iterate modules rather than binaries so shared modules (e.g. authcommon) are covered too.
for gomod in $(find -L . -name go.mod -not -path '*/node_modules/*'); do
    (
        cd $(dirname $gomod)
        echo Testing $PWD
        go test ./...
    )
done
