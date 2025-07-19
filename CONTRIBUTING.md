# Contributing to OCaml Crypto Linter

Thank you for your interest in contributing to OCaml Crypto Linter! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- OCaml version and environment details
- Steps to reproduce the issue
- Expected behavior vs actual behavior
- Code samples that trigger the issue
- Any relevant error messages or logs

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- Use case for the feature
- Proposed implementation approach
- Alternative solutions you've considered
- Any potential breaking changes

### Adding New Rules

To add a new cryptographic vulnerability detection rule:

1. Create a new file in `src/rules/` following the naming convention
2. Implement the rule using the `Rule.t` type:

```ocaml
let my_new_rule : Rule.t = {
  id = "CATEGORY###";
  name = "Descriptive Name";
  description = "What vulnerability this detects";
  severity = Error; (* Critical | Error | Warning | Info *)
  tags = ["relevant"; "tags"];
  check = fun ast -> (* AST analysis logic *)
}
```

3. Register the rule in the appropriate category module
4. Add test cases in `test/rules/`
5. Document the rule in `docs/rules/`

### Pull Request Process

1. Fork the repository and create your branch from `main`
2. Make your changes following the code style guidelines
3. Add or update tests as needed
4. Ensure all tests pass: `dune test`
5. Update documentation if needed
6. Create a Pull Request with a clear description

### Code Style Guidelines

- Follow standard OCaml conventions
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and small
- Use pattern matching over if-then-else when appropriate

### Testing

- Unit tests go in `test/`
- Integration tests go in `test/integration/`
- Test vulnerable patterns in `test/vulnerable/`
- Test secure patterns in `test/secure/`

Run tests with:
```bash
dune test
```

### Documentation

- API documentation uses odoc format
- User documentation goes in `docs/`
- Update README.md for user-facing changes
- Add examples for new features

## Development Setup

```bash
# Clone the repository
git clone https://github.com/ShaiKKO/Vortex.git
cd Vortex/ocaml-crypto-linter

# Install dependencies
opam install . --deps-only --with-test --with-doc

# Build the project
dune build

# Run tests
dune test

# Build documentation
dune build @doc
```

## Rule Categories

When adding rules, use these category prefixes:

- `ALGO###`: Algorithm weaknesses (weak ciphers, hashes)
- `KEY###`: Key and nonce management issues
- `SIDE###`: Side-channel vulnerabilities
- `API###`: API misuse patterns
- `DEP###`: Dependency vulnerabilities
- `RAND###`: Random number generation issues
- `DOS###`: Denial of service vulnerabilities

## Commit Message Guidelines

Follow the conventional commits specification:

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `test:` Test additions or changes
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

Example: `feat(rules): add detection for weak PRNG seeds`

## Release Process

Releases are automated through GitHub Actions when a tag is pushed:

```bash
git tag -a v0.1.0 -m "Release version 0.1.0"
git push origin v0.1.0
```

## Getting Help

- Join our [Discord server](https://discord.gg/ocaml-crypto-linter)
- Check the [documentation](https://shaikko.github.io/Vortex/ocaml-crypto-linter/)
- Open a [discussion](https://github.com/ShaiKKO/Vortex/discussions) for questions

## Recognition

Contributors are recognized in:
- The AUTHORS file
- Release notes
- Project documentation

Thank you for contributing to making OCaml code more secure!