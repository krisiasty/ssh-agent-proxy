#!/bin/sh

set -eu

goreleaser build --clean --snapshot --single-target
/usr/local/bin/ssh-agent-proxy --stop
sudo cp -v -f dist/ssh-agent-proxy*/ssh-agent-proxy /usr/local/bin/ssh-agent-proxy
/usr/local/bin/ssh-agent-proxy --reinstall
/usr/local/bin/ssh-agent-proxy --start
/usr/local/bin/ssh-agent-proxy --status
