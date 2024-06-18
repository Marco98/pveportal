#!/bin/sh
set -eu

git tag -a $1
git push origin $1
goreleaser release --clean
docker push ghcr.io/marco98/pveportal:$1
docker push ghcr.io/marco98/pveportal:latest
