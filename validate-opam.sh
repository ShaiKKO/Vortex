#!/bin/bash
set -e

echo "Validating OPAM package..."

# Check for required files
echo "Checking required files..."
required_files=(
    "ocaml-crypto-linter.opam"
    "dune-project"
    "LICENSE"
    "README.md"
    "CHANGES.md"
)

for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        echo "ERROR: Missing required file: $file"
        exit 1
    fi
done

# Validate OPAM file
echo "Validating OPAM file syntax..."
if command -v opam &> /dev/null; then
    opam lint ocaml-crypto-linter.opam || echo "WARNING: opam lint found issues"
else
    echo "WARNING: opam not installed, skipping lint"
fi

# Check version consistency
echo "Checking version consistency..."
OPAM_VERSION=$(grep -E '^version:' dune-project | sed 's/.*"\(.*\)".*/\1/' || echo "")
FILE_VERSION=$(cat .opam-version 2>/dev/null || echo "")

if [ -z "$OPAM_VERSION" ]; then
    echo "WARNING: No version found in dune-project"
elif [ "$OPAM_VERSION" != "$FILE_VERSION" ]; then
    echo "WARNING: Version mismatch: dune-project ($OPAM_VERSION) vs .opam-version ($FILE_VERSION)"
fi

# Check dependencies
echo "Checking dependencies..."
echo "Required dependencies found in OPAM file:"
grep -E '^\s*"[^"]+"\s*\{' ocaml-crypto-linter.opam | sed 's/.*"\([^"]*\)".*/  - \1/'

# Test build
echo ""
echo "Testing build..."
if command -v dune &> /dev/null; then
    echo "Running: dune build @install"
    dune build @install 2>&1 | tail -20
else
    echo "WARNING: dune not available, skipping build test"
fi

# Summary
echo ""
echo "Validation Summary:"
echo "- Required files: ✓"
echo "- OPAM syntax: Check output above"
echo "- Version: $OPAM_VERSION"
echo "- Ready for release: Review warnings above"
echo ""
echo "To test installation locally:"
echo "  opam pin add ocaml-crypto-linter . -n"
echo "  opam install ocaml-crypto-linter --deps-only"
echo "  opam install ocaml-crypto-linter"