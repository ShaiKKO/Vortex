# Installation Guide

This guide covers all installation methods for OCaml Crypto Linter.

## Prerequisites

- OCaml 4.14.0 or later (5.x recommended for parallel analysis)
- OPAM package manager
- Dune build system (>= 3.15)

## Installation Methods

### 1. Via OPAM (Recommended)

```bash
# Add the package
opam install ocaml-crypto-linter

# Verify installation
ocaml-crypto-linter --version
```

### 2. From Source

```bash
# Clone the repository
git clone https://github.com/ShaiKKO/Vortex.git
cd Vortex/ocaml-crypto-linter

# Install dependencies
opam install . --deps-only --with-test

# Build
dune build

# Install
dune install

# Or use locally without installing
dune exec bin/main.exe -- --help
```

### 3. Using Docker

```bash
# Pull the image
docker pull ghcr.io/shaikko/ocaml-crypto-linter:latest

# Run on current directory
docker run -v $(pwd):/workspace ghcr.io/shaikko/ocaml-crypto-linter /workspace

# Run with custom options
docker run -v $(pwd):/workspace ghcr.io/shaikko/ocaml-crypto-linter \
  /workspace -f json -o report.json
```

### 4. Development Installation

For contributing or modifying the linter:

```bash
# Clone with development setup
git clone https://github.com/ShaiKKO/Vortex.git
cd Vortex/ocaml-crypto-linter

# Install all dependencies including test and doc
opam install . --deps-only --with-test --with-doc

# Build in development mode
dune build @all

# Run tests
dune test

# Build documentation
dune build @doc
```

## Platform-Specific Instructions

### macOS

```bash
# Install system dependencies
brew install gmp pkg-config

# Install OCaml and OPAM
brew install opam
opam init
eval $(opam env)

# Install the linter
opam install ocaml-crypto-linter
```

### Ubuntu/Debian

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y build-essential m4 libgmp-dev pkg-config

# Install OPAM
sudo apt-get install opam
opam init
eval $(opam env)

# Install the linter
opam install ocaml-crypto-linter
```

### Windows (WSL2)

```bash
# In WSL2 Ubuntu
sudo apt-get update
sudo apt-get install -y opam libgmp-dev pkg-config

# Initialize OPAM
opam init --disable-sandboxing
eval $(opam env)

# Install the linter
opam install ocaml-crypto-linter
```

## Optional Dependencies

### Semgrep Integration

For enhanced pattern-based detection:

```bash
# Install Python and pip
sudo apt-get install python3 python3-pip

# Install Semgrep
pip3 install semgrep

# Verify
semgrep --version
```

### Editor Support

For LSP support (experimental):

```bash
opam install ocaml-lsp-server
```

## Verification

After installation, verify everything works:

```bash
# Check version
ocaml-crypto-linter --version

# Run on example
echo 'let key = "hardcoded_key"' > test.ml
ocaml-crypto-linter test.ml

# Expected output should show KEY001 vulnerability
```

## Troubleshooting

### Common Issues

1. **"ocaml-crypto-linter: command not found"**
   ```bash
   # Ensure OPAM environment is set
   eval $(opam env)
   
   # Check installation
   opam list | grep ocaml-crypto-linter
   ```

2. **"No switch is currently set"**
   ```bash
   # Create a switch
   opam switch create 5.2.0
   eval $(opam env)
   ```

3. **Missing dependencies**
   ```bash
   # Reinstall with all dependencies
   opam install ocaml-crypto-linter --deps-only
   opam install ocaml-crypto-linter
   ```

4. **Build failures**
   ```bash
   # Clean and rebuild
   dune clean
   opam reinstall ocaml-crypto-linter
   ```

### Getting Help

If you encounter issues:
1. Check the [FAQ](faq.md)
2. Search [existing issues](https://github.com/ShaiKKO/Vortex/issues)
3. Open a new issue with:
   - OCaml version: `ocaml --version`
   - OPAM version: `opam --version`
   - Error messages
   - Steps to reproduce

## Next Steps

- Read the [Quick Start Guide](quickstart.md)
- Configure the linter for your [project](configuration.md)
- Set up [CI/CD integration](ci-integration.md)