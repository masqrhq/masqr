# Contributing to masqr

Thanks for your interest in helping out. masqr is a small project today; the bar for contributions is "does it make the proxy safer, faster, or easier to integrate without breaking existing behaviour."

## Building & testing

```bash
go build -o masqr .
go test ./...
```

OCR integration tests are skipped unless you point `MASQR_OCR_TEST_IMAGE` at a real JPEG/PNG:

```bash
MASQR_OCR_TEST_IMAGE=/path/to/screenshot.png go test -run TestOCR -v .
```

The repo ships large binary assets (PP-OCRv5 ONNX models + the bundled ONNX runtime) under Git LFS. After cloning:

```bash
git lfs install
git lfs pull
```

Without LFS the `.ocr/*.onnx` and `.ocr/onnxruntime-linux-x64-1.26.0/lib/libonnxruntime.so.1.26.0` files will be 130-byte pointer files and `go build` will fail at the `//go:embed` step.

## Pull-request expectations

- One concern per PR. Easier to review, easier to revert.
- `go test ./...` passes locally.
- New behaviour comes with a test. New rule patterns come with both positive and negative tests (a clear hit and a clear non-hit).
- Updates to `sources_ocr.go` that touch the pipeline run end-to-end against a real image (see above).
- README / CHANGELOG updated when user-visible behaviour or env vars change.

## Code conventions

- **No surprise dependencies.** masqr's value is "single static binary, no network calls beyond the upstream API." A PR that adds a heavyweight transitive dep needs a strong justification.
- **No AGPL / SSPL / non-OSI deps.** Permissive (MIT / Apache-2.0 / BSD) only. The TruffleHog drop in v0.1 was for this reason.
- **Comments explain *why*, not *what*.** Well-named identifiers cover the *what*. Save comments for non-obvious constraints, workarounds, or invariants.
- **Errors get logged, not swallowed.** Use `logOCRError` (or the equivalent for new sources) rather than silent `continue` on failure paths.

## Reporting bugs

Open an issue with:
- The masqr version (`git describe --tags` is fine).
- The exact command line.
- A redacted minimal request body that reproduces the issue.
- What you expected vs what happened.

Security-sensitive findings (e.g. a rule that mis-fires and leaks a secret into the log): see `SECURITY.md` — or, until that exists, email the maintainer at `security@masqr.dev`.

## CLA

We don't have a Contributor License Agreement yet. We plan to introduce one (via [cla-assistant.io](https://cla-assistant.io)) before the project accepts a sustained stream of external contributions, so the option to relicense stays open. By submitting a PR today you agree that your contribution may be relicensed under any future OSI-approved permissive license the maintainer chooses.

## Releasing (maintainers)

```bash
# tag and push
git tag -s vX.Y.Z -m "vX.Y.Z"
git push --tags

# regenerate the binary
go build -ldflags="-X main.version=vX.Y.Z" -o masqr .
```

Releases are published to [GitHub Releases](https://github.com/masqrhq/masqr/releases).
