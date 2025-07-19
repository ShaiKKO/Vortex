# Multi-stage Dockerfile for OCaml Crypto Linter

# Build stage
FROM ocaml/opam:ubuntu-22.04-ocaml-5.2 AS builder

# Install system dependencies
USER root
RUN apt-get update && apt-get install -y \
    libgmp-dev \
    pkg-config \
    m4 \
    && rm -rf /var/lib/apt/lists/*

# Switch to opam user
USER opam

# Copy project files
WORKDIR /home/opam/ocaml-crypto-linter
COPY --chown=opam:opam . .

# Install OCaml dependencies
RUN opam install . --deps-only -y

# Build the project
RUN eval $(opam env) && dune build --profile release

# Runtime stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libgmp10 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash linter

# Copy binary from build stage
COPY --from=builder /home/opam/ocaml-crypto-linter/_build/default/bin/main.exe /usr/local/bin/ocaml-crypto-linter

# Copy Semgrep rules if any
COPY --from=builder /home/opam/ocaml-crypto-linter/rules /opt/ocaml-crypto-linter/rules

# Set up working directory
WORKDIR /workspace
RUN chown linter:linter /workspace

# Switch to non-root user
USER linter

# Set environment variables
ENV OCAML_CRYPTO_LINTER_RULES_PATH=/opt/ocaml-crypto-linter/rules
ENV OCAML_CRYPTO_LINTER_OUTPUT_FORMAT=json

# Default command
ENTRYPOINT ["ocaml-crypto-linter"]
CMD ["--help"]