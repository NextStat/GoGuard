# GoGuard

**Mathematical data flow security for Go.** 

GoGuard is a high-performance Rust static analysis engine taking Go SSA via a FlatBuffers "Fat Bridge" to catch nil dereferences, unhandled errors, and data races at compile time.

It is 100% free, open-source, and entirely devoid of paid enterprise tiers. We believe in providing absolute mathematical safety and maximum performance for everyone in the Go ecosystem.

Designed from the ground up to be natively accessible for AI Agents via MCP (Model Context Protocol).

## Why GoGuard?

Go's compiler catches syntax and type errors but permits a subclass of panics and subtle runtime issues:
- **Nil pointer dereferences** (any pointer can be nil)
- **Silently ignored errors**
- **Data races without compile-time protection**
- **Resource leaks** (goroutines, unclosed files)

GoGuard uses abstract interpretation (dataflow analysis) to verify these properties mathematically, going beyond simple AST pattern matching.

## Key Features

- **Abstract Interpretation:** Employs fixed-point forward dataflow analysis to guarantee nil-safety and resource lifecycle correct handling.
- **Rust Performance:** High-speed execution capable of analyzing massive monorepos in milliseconds. Incremental caching powered by Salsa.
- **FlatBuffers "Fat Bridge":** We let Go's official `go/packages` and `go/ssa` handle the parsing and type checking, then instantly serialize the entire SSA IR over an optimized zero-copy FlatBuffers bridge directly to Rust. 
- **AI-Native (MCP):** Exposes a first-class Model Context Protocol server. AI agents (like Claude Code and Cursor) can dynamically verify their own code with mathematical proof before suggesting it to you.
- **100% Free & Open Source:** GoGuard is licensed under MIT OR Apache-2.0. There are no paid features, pro tiers, or enterprise locks.

## Getting Started

*(Wait for the initial release... coming soon!)*

## Contributing

We welcome community contributions! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to get started.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE).
