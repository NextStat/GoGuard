# Contributing to GoGuard

First of all, thank you for considering contributing to GoGuard! 🚀

GoGuard is 100% free and open-source software, built with mathematical rigor at the compilation level for the entire Go ecosystem. 

## How We Work

GoGuard is a dual-language project:
- **Go** is used inside the `goguard-go-bridge`, which relies on `go/packages` and `go/ssa` to parse Go code and compile it into an SSA control flow graph.
- **Rust** is our main engine, consuming a zero-copy FlatBuffers payload ("Fat Bridge") and executing high-performance fixed-point forward dataflow analysis and MCP server logic.

## Contribution Guidelines

* **Testing:** Every PR should strive to pass our test suite. Rust code should use `cargo test`, while the Go bridge has its own `go test ./...` suites.
* **Rust Formatting:** Ensure you run `cargo fmt` and `cargo clippy`. We strive for 0 clippy warnings.
* **Open Source First:** There are no enterprise rules or paid functionality in GoGuard. Features added should benefit all developers freely and openly.

## Step-by-Step

1. Fork the GoGuard repository.
2. Create your feature branch (`git checkout -b feature/amazing-feature`).
3. Commit your changes (`git commit -m 'feat: add some amazing feature'`).
4. Push to the branch (`git push origin feature/amazing-feature`).
5. Open a Pull Request.

## Issues

Feel free to open issues for bug reports, enhancement/feature requests, and discussions!
