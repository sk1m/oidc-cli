#!/bin/sh

set -e

rm -rf completions
mkdir completions

for sh in bash zsh fish; do
	go run ./cmd/oidc/main.go completion "$sh" > "completions/oidc.$sh"
done
