# External screenshot fixtures

Real-world test images sourced from other open-source PII / secret-scanning
projects. These are **not** leaked screenshots from the wild — every image
here was created and published by its upstream project specifically as test
data, with intentionally synthetic content (fictional names, reserved-range
phone numbers like `555-0121`, `@microsoft.com` test addresses) so that
secret-scanner regression suites can stand on a common corpus.

All files are committed verbatim from the upstream repos under their
respective open-source licences, with the SHA-256 below to detect drift on
future re-fetch.

## Files

| File | Source | Upstream URL | Licence | SHA-256 |
|---|---|---|---|---|
| `presidio-ocr_test.png` | Microsoft Presidio | [github.com/microsoft/presidio @ `main/presidio-image-redactor/tests/integration/resources/ocr_test.png`](https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/tests/integration/resources/ocr_test.png) | MIT | `a5bf5a039c53821391a7c2f19328bc95c0501276413bf8b02f85f9f9f8c8fdb0` |
| `presidio-pii_verify.png` | Microsoft Presidio | [github.com/microsoft/presidio @ `main/presidio-image-redactor/tests/integration/resources/pii_verify.png`](https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/tests/integration/resources/pii_verify.png) | MIT | `da774ea0cbcb64e88f288b719166e280824fc557314a91c9feaab0a1bcf09adc` |

## What masqr extracts from each

### `presidio-ocr_test.png` — sample only, not asserted
Contributor-License-Agreement excerpt with intentionally synthetic PII:
- `David Johnson` — fictional person name (masqr does not flag names today)
- `(212) 555-1234` — reserved fictional phone number (no current masqr rule)
- `cla.microsoft.com` — vendor URL (not a secret)
- `opencode@microsoft.com` — should fire `email-address/from-image` but
  **doesn't reliably**, see below.

`ocr_test.png` is committed to demonstrate a real-world OCR recall edge
case in masqr's `sources_ocr.go` pipeline rather than to gate CI. The
image is a 1098 px-wide screenshot whose every paragraph spans the full
canvas width. PaddleOCR PP-OCRv5's detection model finds those lines
fine — every paragraph becomes one detection box — but the recognition
model squashes every crop to a fixed `recInputW=320 px` input, and
1098 → 320 squashes the glyphs past the legibility threshold. The
`email-address` line `opencode@microsoft.com with any additional
questions or comments.` lives inside a 1098 px-wide box, so the rec
model returns garbage and the email is never extracted.

This is the same constraint that drives `scripts/generate-screenshots.py`
to keep every line under ~24 mono chars. Fixing the limitation in
`sources_ocr.go` (split wide boxes into rec-friendly chunks before
inference) is tracked separately from this corpus.

### `presidio-pii_verify.png` — asserted by Phase E
The same CLA excerpt overlaid with Presidio's own PII bounding-box
annotations rendered into the image. The overlays happen to split the
long paragraph lines into many narrower detection boxes — one of which
isolates `ppencde@microsoft.com wi` (~446 px wide), comfortably inside
the rec model's aspect-ratio budget. PP-OCRv5 reads it accurately
enough that the `email-address` regex matches and the `from-image`
source surfaces it. This is the Phase E assertion.

## Why we don't include real leaked screenshots

masqr's E2E intentionally avoids any screenshot of real-world PII or
credentials, even ones already publicly leaked. Downloading and committing
those to source control:

1. **Re-distributes other people's private data** without their consent —
   privacy violations don't get cured by being downstream of a leak.
2. **Re-distributes compromised credentials** — even if a key has been
   "burned" upstream, committing it here propagates it further, ages slower,
   and turns this repo into a future hit for credential-harvesting crawlers.
3. **Adds no detection signal** — the canonical fictional vectors
   (`AKIAIOSFODNN7EXAMPLE`, `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
   `555-01XX`, `4532015112830366`) trip exactly the same rules that real
   secrets would, because the rules match on structure not provenance.

If you want to evaluate masqr against your own real screenshots, run
`./masqr` against them locally — that data never leaves your machine.
