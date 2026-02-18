# Contributing to Shinkai Shoujo

Thank you for your interest in contributing to Shinkai Shoujo!

## Getting Started

```bash
git clone https://github.com/0xKirisame/shinkai-shoujo
cd shinkai-shoujo
go mod download
go test ./...
```

## Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Make your changes
4. Run tests (`make test`)
5. Run vet (`make vet`)
6. Commit and push your branch
7. Open a pull request

## Areas Needing Help

- AWS SDK special cases (e.g. `lambda:Invoke` → `lambda:InvokeFunction`)
- Web UI design
- Multi-cloud support (GCP, Azure)
- Documentation improvements

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep exported APIs documented
- Add tests for new functionality

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
