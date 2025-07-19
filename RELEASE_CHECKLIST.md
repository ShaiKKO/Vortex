# Release Checklist for OCaml Crypto Linter

## Pre-release

- [ ] Update version number in:
  - [ ] `dune-project`
  - [ ] `.opam-version`
  - [ ] `CHANGES.md`
  - [ ] Documentation

- [ ] Code quality:
  - [ ] All tests pass: `dune test`
  - [ ] No compiler warnings: `dune build @all`
  - [ ] Documentation builds: `dune build @doc`
  - [ ] Examples work correctly

- [ ] Update documentation:
  - [ ] README.md is current
  - [ ] API documentation is complete
  - [ ] CHANGES.md has release notes
  - [ ] Migration guide (if breaking changes)

## Release Process

1. **Prepare release**
   ```bash
   ./prepare-release.sh 0.1.0
   ```

2. **Test local installation**
   ```bash
   opam pin add ocaml-crypto-linter ./release/ocaml-crypto-linter.0.1.0
   opam install ocaml-crypto-linter
   ocaml-crypto-linter --version
   ```

3. **Create git tag**
   ```bash
   git tag -a v0.1.0 -m "Release version 0.1.0"
   git push origin v0.1.0
   ```

4. **Create GitHub Release**
   - Go to https://github.com/ShaiKKO/Vortex/releases/new
   - Select tag `v0.1.0`
   - Title: "OCaml Crypto Linter v0.1.0"
   - Upload `ocaml-crypto-linter-0.1.0.tar.gz`
   - Copy content from `RELEASE_NOTES_0.1.0.md`
   - Publish release

5. **Submit to OPAM**
   ```bash
   # Fork and clone opam-repository
   git clone https://github.com/ocaml/opam-repository.git
   cd opam-repository
   
   # Create package directory
   mkdir -p packages/ocaml-crypto-linter/ocaml-crypto-linter.0.1.0
   
   # Copy opam file
   cp ../release/ocaml-crypto-linter.0.1.0/opam \
      packages/ocaml-crypto-linter/ocaml-crypto-linter.0.1.0/
   
   # Create PR
   git checkout -b add-ocaml-crypto-linter-0.1.0
   git add .
   git commit -m "Add ocaml-crypto-linter.0.1.0"
   git push origin add-ocaml-crypto-linter-0.1.0
   ```

6. **Update documentation site**
   ```bash
   dune build @doc
   # Deploy to GitHub Pages
   ```

## Post-release

- [ ] Verify OPAM installation works: `opam install ocaml-crypto-linter`
- [ ] Update version in `dune-project` to next development version
- [ ] Announce release:
  - [ ] OCaml Discuss forum
  - [ ] Twitter/Social media
  - [ ] OCaml Weekly News
- [ ] Monitor for issues/feedback

## Rollback Plan

If critical issues are found:

1. Delete GitHub release (keep tag)
2. Fix issues
3. Create new patch release (e.g., 0.1.1)
4. Cancel OPAM PR if not merged

## Version Numbering

- MAJOR.MINOR.PATCH following SemVer
- MAJOR: Breaking API changes
- MINOR: New features, backward compatible
- PATCH: Bug fixes only