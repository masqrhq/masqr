# masqr red-team report — `20260620-213351-4106324`

- **Generated:** 2026-06-20T21:33:52+0000
- **Coverage:** 4/14 payloads caught (**28.6%**)
- **New this run:** 0 regression(s), 0 new gap(s); 0 newly fixed

<details><summary>⚪ Known gaps (already on record)</summary>

| Secret | Technique | Class | Origin |
|--------|-----------|-------|--------|
| `aws-access-key-id` | `base32` | known_gap | seed |
| `aws-access-key-id` | `hex` | known_gap | seed |
| `aws-access-key-id` | `url_percent` | known_gap | seed |
| `aws-access-key-id` | `html_entities` | known_gap | seed |
| `aws-access-key-id` | `gzip_b64` | known_gap | seed |
| `github-pat` | `base32` | known_gap | seed |
| `github-pat` | `hex` | known_gap | seed |
| `github-pat` | `url_percent` | known_gap | seed |
| `github-pat` | `html_entities` | known_gap | seed |
| `github-pat` | `gzip_b64` | known_gap | seed |

</details>

✅ No new evasion gaps or regressions this run.

> Reproducible missed payloads: `redteam-gaps.jsonl`. Values are documentation-only samples.

## Fix verification (built & checked locally)
- `go build` + `go vet` + `go test` + re-scan gate: **ok**
- the rebuilt masqr now catches **all 10** previously-missed payload(s) ✅
