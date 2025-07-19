# OCaml Crypto Linter Documentation

Welcome to the OCaml Crypto Linter documentation. This tool helps detect cryptographic vulnerabilities in OCaml codebases through static analysis.

## Documentation Overview

### Getting Started
- [Installation Guide](guides/installation.md) - How to install and configure the linter
- [Quick Start Guide](guides/quickstart.md) - Get up and running in 5 minutes
- [CLI Reference](guides/cli-reference.md) - Complete command-line interface documentation

### User Guides
- [Configuration](guides/configuration.md) - Configuring the linter for your project
- [CI/CD Integration](guides/ci-integration.md) - Integrating with GitHub Actions, GitLab CI, etc.
- [IDE Integration](guides/ide-integration.md) - Using the linter in VS Code, Emacs, and Vim
- [Output Formats](guides/output-formats.md) - Understanding JSON, SARIF, and text outputs

### Security Rules
- [Rule Catalog](rules/index.md) - Complete list of all security rules
- [Algorithm Weakness Rules](rules/algorithm-weakness.md) - Detecting weak cryptographic algorithms
- [Key Management Rules](rules/key-management.md) - Finding key and nonce vulnerabilities
- [Side-Channel Rules](rules/side-channel.md) - Identifying timing and side-channel attacks
- [API Misuse Rules](rules/api-misuse.md) - Catching incorrect API usage

### Developer Documentation
- [Architecture Overview](architecture.md) - System design and components
- [Writing Custom Rules](guides/writing-rules.md) - Extending the linter with new rules
- [API Reference](api/index.md) - Module documentation for library usage
- [Contributing Guide](../CONTRIBUTING.md) - How to contribute to the project

### Examples
- [Common Vulnerabilities](examples/common-vulnerabilities.md) - Examples of detected issues
- [Secure Patterns](examples/secure-patterns.md) - Recommended secure coding patterns
- [Integration Examples](examples/integration-examples.md) - Real-world integration scenarios

## Quick Links

- [GitHub Repository](https://github.com/ShaiKKO/Vortex)
- [Issue Tracker](https://github.com/ShaiKKO/Vortex/issues)
- [Release Notes](../CHANGES.md)
- [License](../LICENSE)

## Version

Current version: 0.1.0

## Support

For questions and support:
- Open an [issue](https://github.com/ShaiKKO/Vortex/issues) on GitHub
- Check the [FAQ](guides/faq.md)
- Join the discussion on [GitHub Discussions](https://github.com/ShaiKKO/Vortex/discussions)