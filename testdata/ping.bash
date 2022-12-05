#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

Check() {
    if grep -E "Port :| IP :" dump.txt; then
        exit 0
    else
        exit 1
    fi
}

git clone -b starting_tasks "$CIRRUS_REPO_CLONE_URL" && cd heteronculous-horklump


go run main.go >> dump.txt & sleep 10 ; Check