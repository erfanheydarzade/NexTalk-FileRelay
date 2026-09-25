# Contributing to NexTalk-FileRelay

Thank you for your interest in contributing! This document covers how to get started.

## Development Setup

```bash
# Clone and enter the repo
git clone https://github.com/erfanheydarzade/NexTalk-FileRelay.git
cd NexTalk-FileRelay

# Install Go dependencies
go mod download

# Run tests
go test ./... -v

# Build locally
go build -o filerelayd ./cmd/filerelayd
```

## Coding Conventions

- Follow [Effective Go](https://go.dev/doc/effective_go) and [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use `gofmt` for formatting (enforced by CI)
- Run `go vet ./...` before committing
- Keep dependencies minimal — prefer stdlib + well-established packages

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) format:

```
feat(relay): add chunked upload support
fix(auth): validate pubkey length before processing
docs: update API reference with new rate-limit header
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

## Pull Requests

1. Fork the repo and create a branch named `feature/your-feature` or `fix/your-fix`
2. Make sure CI passes (`go build`, `go vet`, `gofmt`)
3. Open a PR with a clear description of what changed and why
4. Link any related issues

## Releasing

See [docs/RELEASING.md](docs/RELEASING.md) for the full release process. Quick summary:

```bash
# Tag a release (also triggers the GitHub Actions Release workflow)
git tag v0.1.0
git push origin --tags

# Or use the "Run Workflow" button in Actions and specify version manually
```

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 license.
