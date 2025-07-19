#!/bin/bash
set -e

# OCaml Crypto Linter Release Preparation Script

VERSION="${1:-0.1.0}"
OPAM_REPO="${OPAM_REPO:-../opam-repository}"

echo "Preparing OCaml Crypto Linter release v${VERSION}..."

# 1. Update version in dune-project
echo "Updating version in dune-project..."
sed -i.bak "s/(version [^)]*)/version ${VERSION})/" dune-project && rm dune-project.bak

# 2. Generate OPAM files
echo "Generating OPAM files..."
dune build @install || true

# 3. Create release directory structure
RELEASE_DIR="release/ocaml-crypto-linter.${VERSION}"
mkdir -p "${RELEASE_DIR}"

# 4. Copy essential files
echo "Copying release files..."
cp ocaml-crypto-linter.opam "${RELEASE_DIR}/opam"
cp LICENSE "${RELEASE_DIR}/"
cp README.md "${RELEASE_DIR}/"
cp CONTRIBUTING.md "${RELEASE_DIR}/"

# 5. Create release tarball
echo "Creating release tarball..."
tar czf "ocaml-crypto-linter-${VERSION}.tar.gz" \
  --exclude='.git' \
  --exclude='_build' \
  --exclude='release' \
  --exclude='.github' \
  --exclude='*.tar.gz' \
  .

# 6. Generate checksum
echo "Generating checksum..."
if command -v sha256sum &> /dev/null; then
    sha256sum "ocaml-crypto-linter-${VERSION}.tar.gz" > "ocaml-crypto-linter-${VERSION}.tar.gz.sha256"
else
    shasum -a 256 "ocaml-crypto-linter-${VERSION}.tar.gz" > "ocaml-crypto-linter-${VERSION}.tar.gz.sha256"
fi

# 7. Update OPAM file with archive info
CHECKSUM=$(cat "ocaml-crypto-linter-${VERSION}.tar.gz.sha256" | cut -d' ' -f1)
cat >> "${RELEASE_DIR}/opam" << EOF

url {
  src: "https://github.com/ShaiKKO/Vortex/releases/download/v${VERSION}/ocaml-crypto-linter-${VERSION}.tar.gz"
  checksum: [
    "sha256=${CHECKSUM}"
  ]
}
EOF

# 8. Prepare OPAM repository submission
if [ -d "${OPAM_REPO}" ]; then
    echo "Preparing OPAM repository submission..."
    OPAM_PKG_DIR="${OPAM_REPO}/packages/ocaml-crypto-linter/ocaml-crypto-linter.${VERSION}"
    mkdir -p "${OPAM_PKG_DIR}"
    cp "${RELEASE_DIR}/opam" "${OPAM_PKG_DIR}/opam"
    echo "OPAM package prepared at: ${OPAM_PKG_DIR}"
else
    echo "OPAM repository not found. Clone https://github.com/ocaml/opam-repository to submit."
fi

# 9. Create release notes
cat > "RELEASE_NOTES_${VERSION}.md" << EOF
# OCaml Crypto Linter v${VERSION}

## Features
- AST-based cryptographic vulnerability detection
- Support for Cryptokit, Nocrypto, and Mirage-crypto
- 30+ security rules across 7 categories
- Interprocedural dataflow analysis
- Context-aware false positive reduction
- Multiple output formats (JSON, SARIF, text)

## Installation
\`\`\`bash
opam install ocaml-crypto-linter
\`\`\`

## Changelog
- Initial release with core functionality
- Support for OCaml 4.14+ and 5.x
- Parallel analysis using OCaml 5 domains
- CI/CD integration examples

## Known Issues
- Semgrep integration requires manual installation
- LSP support is experimental

## Next Release
- Additional vulnerability patterns
- IDE plugin support
- Performance optimizations
EOF

echo ""
echo "Release preparation complete!"
echo ""
echo "Next steps:"
echo "1. Review generated files in release/"
echo "2. Test installation: opam pin add ocaml-crypto-linter ./release/ocaml-crypto-linter.${VERSION}"
echo "3. Create GitHub release and upload tarball"
echo "4. Submit PR to opam-repository"
echo ""
echo "Files created:"
echo "- ocaml-crypto-linter-${VERSION}.tar.gz"
echo "- ocaml-crypto-linter-${VERSION}.tar.gz.sha256"
echo "- ${RELEASE_DIR}/opam"
echo "- RELEASE_NOTES_${VERSION}.md"