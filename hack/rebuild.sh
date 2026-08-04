goreleaser build --clean --snapshot --single-target
/usr/local/bin/ssh-agent-proxy --stop
sudo cp dist/ssh-agent-proxy_darwin_arm64_v8.0/ssh-agent-proxy /usr/local/bin/ssh-agent-proxy
/usr/local/bin/ssh-agent-proxy --reinstall
/usr/local/bin/ssh-agent-proxy --start
/usr/local/bin/ssh-agent-proxy --status
