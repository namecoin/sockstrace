#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

git clone "$CIRRUS_REPO_CLONE_URL" && cd Starting_Tasks
cd "$TASK_NUMBER" && cd Testing_application
export GOBIN="$PWD" && go install hello.go
cd ..

go run main.go
