# Contributing

Thank you for improving `ssh-agent-proxy`.

## Before opening an issue

- Use the bug or enhancement issue form and search existing issues first.
- Include the application version, operating system, architecture, installation
  method, and upstream SSH agent when reporting a bug.
- Sanitize logs and configuration examples. Key fingerprints and comments are
  public-key metadata, but they can still identify a person or organization.
- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Development

Install the Go version declared in `go.mod`, then run:

```sh
go mod tidy
go mod verify
gofmt -w .
go vet ./...
go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
```

Use `actionlint` when changing files under `.github/workflows`. To validate release
packaging without publishing anything, run:

```sh
goreleaser release --snapshot --clean --skip=publish
```

## Pull requests

- Keep each pull request focused and explain its user-visible impact.
- Add or update tests for behavior changes, especially authorization and concurrency
  paths.
- Update the README and architecture documentation when behavior or design changes.
- Do not commit generated binaries, credentials, local configuration, or real key
  metadata.
- Ensure all CI checks pass. A maintainer creates releases after merging; pull requests
  must not change or create release tags.
