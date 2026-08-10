#!/bin/sh

set -eu

dependency_modules=$(mktemp "${TMPDIR:-/tmp}/ssh-agent-proxy-dependencies.XXXXXX")
dependency_modules_raw=$(mktemp "${TMPDIR:-/tmp}/ssh-agent-proxy-dependencies-raw.XXXXXX")
notice_modules=$(mktemp "${TMPDIR:-/tmp}/ssh-agent-proxy-notices.XXXXXX")
trap 'rm -f "$dependency_modules" "$dependency_modules_raw" "$notice_modules"' EXIT

for goos in darwin linux; do
  for goarch in amd64 arm64; do
    GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 go list -deps \
      -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{end}}{{end}}' . \
      >>"$dependency_modules_raw"
  done
done
sed '/^$/d' "$dependency_modules_raw" | sort -u >"$dependency_modules"
sed -n 's/^Module: //p' THIRD_PARTY_NOTICES | sort >"$notice_modules"

if ! diff -u "$dependency_modules" "$notice_modules"; then
  echo "THIRD_PARTY_NOTICES does not match the current module graph" >&2
  exit 1
fi
