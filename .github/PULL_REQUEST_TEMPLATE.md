### What this PR does

<!-- One paragraph. Why is this change happening? -->

### Test plan

<!--
- [ ] `go test ./...` passes locally
- [ ] If touching `sources_ocr.go`: `MASQR_OCR_TEST_IMAGE=/path/to/image.jpg go test -run TestOCR -v .` passes
- [ ] If adding a rule: positive + negative test cases in `*_test.go`
- [ ] README / CHANGELOG updated if behaviour or env vars changed
-->

### Checklist

- [ ] Single concern (easier to review, easier to revert)
- [ ] No new AGPL / SSPL / non-OSI dependencies (see CONTRIBUTING.md §Code conventions)
- [ ] Comments explain *why*, not *what*
- [ ] Errors are logged, not swallowed
