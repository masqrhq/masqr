---
name: Bug report
about: Something masqr does (or fails to do) is wrong
title: "[bug] "
labels: bug
---

### What happened

<!-- One paragraph. What did you expect, what actually happened. -->

### Reproduction

<!--
Exact command line:
  masqr -a 127.0.0.1:8080 claude ...

Minimal request body (redact secrets):
  curl -X POST ...

If OCR-related, include the image (or a synthetic one with the same characteristics).
-->

### Environment

- masqr version: <!-- `masqr --version` or commit sha -->
- OS / arch: <!-- e.g. macOS 14.5 / arm64 -->
- Go version (if built from source): <!-- `go version` -->
- LLM CLI in use: <!-- claude, gemini, codex, … -->

### Logs

<!--
Relevant lines from the session log at masqr-<TIMESTAMP>.log.
Redact secrets before pasting.
-->

```
(paste here)
```
