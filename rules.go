/*
Copyright 2026 masqr contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import "regexp"

// defaultRules returns the built-in rule set. Patterns derive from gitleaks
// and Microsoft Presidio rule families; tuned for prompt-traffic scanning
// where false positives are costlier than the occasional miss.
//
// The Presidio-derived rules are split out into presidioRules() (letter-bearing
// IDs) and the consolidated digit-cluster classifier in digitIDSource (purely
// numeric IDs). Keeping numeric IDs in one shared scan avoids running ~15
// keywordless regex passes per request.
func defaultRules() []Rule {
	mk := regexp.MustCompile
	rules := []Rule{
		// ─── Secrets (Tier-1 — credential leaks) ─────────────────────────
		{
			ID: "aws-access-key-id", Category: "secret", Severity: SevCritical,
			Keywords: []string{"AKIA", "ASIA"},
			Pattern:  mk(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
		},
		{
			ID: "aws-secret-access-key", Category: "secret", Severity: SevCritical,
			Keywords: []string{"aws_secret", "aws-secret"},
			Pattern:  mk(`(?i)aws[_-]secret[_-]?(?:access[_-])?key["'\s:=]+([A-Za-z0-9/+=]{40})`),
		},
		{
			ID: "github-pat", Category: "secret", Severity: SevCritical,
			Keywords: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
			Pattern:  mk(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`),
		},
		{
			ID: "github-fine-grained-pat", Category: "secret", Severity: SevCritical,
			Keywords: []string{"github_pat_"},
			Pattern:  mk(`\bgithub_pat_[A-Za-z0-9_]{82}\b`),
		},
		{
			ID: "anthropic-api-key", Category: "secret", Severity: SevCritical,
			Keywords: []string{"sk-ant-"},
			Pattern:  mk(`\bsk-ant-[a-z0-9-]+\b`),
		},
		{
			ID: "openai-api-key", Category: "secret", Severity: SevCritical,
			Keywords: []string{"sk-proj-", "sk-svcacct-"},
			Pattern:  mk(`\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,}\b`),
		},
		{
			ID: "stripe-live-key", Category: "secret", Severity: SevCritical,
			Keywords: []string{"sk_live_", "rk_live_"},
			Pattern:  mk(`\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b`),
		},

		// ─── GitLab tokens ───────────────────────────────────────────────
		// Prefix taxonomy: https://docs.gitlab.com/ee/security/token_overview.html
		{
			ID: "gitlab-pat", Category: "secret", Severity: SevCritical,
			Keywords: []string{"glpat-"},
			Pattern:  mk(`\bglpat-[0-9A-Za-z_\-]{20,}\b`),
		},
		{
			ID: "gitlab-oauth-app-secret", Category: "secret", Severity: SevCritical,
			Keywords: []string{"gloas-"},
			Pattern:  mk(`\bgloas-[0-9A-Za-z_\-]{40,}\b`),
		},
		{
			ID: "gitlab-pipeline-trigger", Category: "secret", Severity: SevHigh,
			Keywords: []string{"glptt-"},
			Pattern:  mk(`\bglptt-[0-9A-Za-z_\-]{40,}\b`),
		},
		{
			ID: "gitlab-runner-token", Category: "secret", Severity: SevHigh,
			Keywords: []string{"glrt-"},
			Pattern:  mk(`\bglrt-[0-9A-Za-z_\-]{20,}\b`),
		},
		{
			ID: "gitlab-deploy-token", Category: "secret", Severity: SevHigh,
			Keywords: []string{"gldt-"},
			Pattern:  mk(`\bgldt-[0-9A-Za-z_\-]{20,}\b`),
		},
		{
			ID: "gitlab-feed-token", Category: "secret", Severity: SevMedium,
			Keywords: []string{"glft-"},
			Pattern:  mk(`\bglft-[0-9A-Za-z_\-]{20,}\b`),
		},
		{
			ID: "gitlab-agent-token", Category: "secret", Severity: SevHigh,
			Keywords: []string{"glagent-"},
			Pattern:  mk(`\bglagent-[0-9A-Za-z_\-]{50,}\b`),
		},
		{
			ID: "gitlab-scim-token", Category: "secret", Severity: SevCritical,
			Keywords: []string{"glsoat-"},
			Pattern:  mk(`\bglsoat-[0-9A-Za-z_\-]{40,}\b`),
		},
		{
			ID: "gitlab-ci-job-token", Category: "secret", Severity: SevHigh,
			Keywords: []string{"glcbt-"},
			Pattern:  mk(`\bglcbt-[0-9A-Za-z_\-]{20,}\b`),
		},
		{
			ID: "slack-bot-or-user-token", Category: "secret", Severity: SevCritical,
			Keywords: []string{"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"},
			Pattern:  mk(`\bxox[abprs]-\d+-\d+-[A-Za-z0-9-]{20,}\b`),
		},
		{
			ID: "slack-webhook", Category: "secret", Severity: SevHigh,
			Keywords: []string{"hooks.slack.com"},
			Pattern:  mk(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`),
		},
		{
			ID: "jwt", Category: "secret", Severity: SevMedium,
			Keywords: []string{"eyJ"},
			Pattern:  mk(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
		},
		{
			ID: "private-key-pem", Category: "secret", Severity: SevCritical,
			Keywords: []string{"-----BEGIN"},
			Pattern:  mk(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |)PRIVATE KEY-----`),
		},

		// ─── Attachments (images / docs / audio / files) ────────────────
		// Anthropic API content blocks. Severity reflects information
		// content: PDFs and audio/video usually carry more sensitive data
		// than inline images (which are often deliberately shared screenshots).
		{
			ID: "attachment-image-inline", Category: "attachment", Severity: SevMedium,
			Keywords: []string{`"image/`},
			Pattern:  mk(`"media_type"\s*:\s*"image/[a-z0-9.+-]+"`),
		},
		{
			ID: "attachment-pdf-inline", Category: "attachment", Severity: SevHigh,
			Keywords: []string{`"application/pdf"`},
			Pattern:  mk(`"media_type"\s*:\s*"application/pdf"`),
		},
		{
			ID: "attachment-audio-inline", Category: "attachment", Severity: SevHigh,
			Keywords: []string{`"audio/`},
			Pattern:  mk(`"media_type"\s*:\s*"audio/[a-z0-9.+-]+"`),
		},
		{
			ID: "attachment-video-inline", Category: "attachment", Severity: SevHigh,
			Keywords: []string{`"video/`},
			Pattern:  mk(`"media_type"\s*:\s*"video/[a-z0-9.+-]+"`),
		},
		{
			ID: "attachment-file-reference", Category: "attachment", Severity: SevHigh,
			Keywords: []string{`"file_id"`},
			Pattern:  mk(`"file_id"\s*:\s*"file_[A-Za-z0-9_]{6,}"`),
		},
		{
			ID: "attachment-url-source", Category: "attachment", Severity: SevLow,
			Keywords: []string{`"type":"url"`, `"type": "url"`},
			Pattern:  mk(`"source"\s*:\s*\{[^}]{0,200}"type"\s*:\s*"url"`),
		},
		{
			ID: "attachment-document-block", Category: "attachment", Severity: SevMedium,
			Keywords: []string{`"type":"document"`, `"type": "document"`},
			Pattern:  mk(`"type"\s*:\s*"document"`),
		},

		// ─── Generic encoded blobs ───────────────────────────────────────
		{
			ID: "generic-base64-blob", Category: "secret", Severity: SevLow,
			// No keyword — runs unconditionally. Validate gates by entropy
			// so we don't flag every long hex-ish identifier.
			Pattern: mk(`[A-Za-z0-9+/]{24,}={0,2}`),
			Validate: func(s string) bool {
				return isHighEntropyBase64(s)
			},
		},

		// ─── GCP ─────────────────────────────────────────────────────────
		{
			ID: "gcp-api-key", Category: "gcp", Severity: SevHigh,
			Keywords: []string{"AIza"},
			Pattern:  mk(`\bAIza[0-9A-Za-z_-]{35}\b`),
		},
		{
			ID: "gcp-service-account-key", Category: "gcp", Severity: SevCritical,
			Keywords: []string{`"type": "service_account"`, `"type":"service_account"`},
			Pattern:  mk(`"type"\s*:\s*"service_account"`),
		},
		{
			ID: "gcp-oauth-client-id", Category: "gcp", Severity: SevLow,
			Keywords: []string{".apps.googleusercontent.com"},
			Pattern:  mk(`\b\d+-[a-z0-9_-]{20,}\.apps\.googleusercontent\.com\b`),
		},

		// ─── Azure ───────────────────────────────────────────────────────
		{
			ID: "azure-storage-conn-string", Category: "azure", Severity: SevCritical,
			Keywords: []string{"DefaultEndpointsProtocol"},
			Pattern:  mk(`DefaultEndpointsProtocol=https?;[^\s"']*AccountKey=[A-Za-z0-9+/=]{40,}`),
		},
		{
			ID: "azure-storage-account-key", Category: "azure", Severity: SevCritical,
			Keywords: []string{"AccountKey="},
			Pattern:  mk(`AccountKey=[A-Za-z0-9+/=]{86,90}`),
		},
		{
			ID: "azure-service-bus-conn", Category: "azure", Severity: SevHigh,
			Keywords: []string{".servicebus.windows.net"},
			Pattern:  mk(`Endpoint=sb://[^;]+\.servicebus\.windows\.net[^;]*;SharedAccessKey(?:Name)?=[^;\s"']+`),
		},
		{
			ID: "azure-cosmos-conn", Category: "azure", Severity: SevCritical,
			Keywords: []string{".documents.azure.com"},
			Pattern:  mk(`AccountEndpoint=https?://[^;]+\.documents\.azure\.com[^;]*;AccountKey=[A-Za-z0-9+/=]{40,}`),
		},
		{
			ID: "azure-sql-conn", Category: "azure", Severity: SevCritical,
			Keywords: []string{".database.windows.net"},
			Pattern:  mk(`Server=tcp:[^,]+\.database\.windows\.net,1433;[^"']*Password=[^;\s"']+`),
		},

		// ─── Swiss PII ───────────────────────────────────────────────────
		{
			ID: "ch-ahv", Category: "pii-ch", Severity: SevHigh,
			Keywords: []string{"756."},
			Pattern:  mk(`\b756\.\d{4}\.\d{4}\.\d{2}\b`),
			Validate: ahvCheck,
		},
		{
			ID: "ch-uid", Category: "pii-ch", Severity: SevMedium,
			Keywords: []string{"CHE-"},
			Pattern:  mk(`\bCHE-\d{3}\.\d{3}\.\d{3}\b`),
			Validate: uidCheck,
		},
		{
			ID: "ch-iban", Category: "pii-ch", Severity: SevHigh,
			Keywords: []string{"CH"},
			Pattern:  mk(`\bCH\d{2}(?:\s?\d{4}){4}\s?\d\b`),
			Validate: ibanMod97,
		},
		{
			ID: "ch-postfinance-account", Category: "pii-ch", Severity: SevLow,
			Keywords: []string{"-"}, // weak anchor — accept some false positives
			Pattern:  mk(`\b\d{2}-\d{1,6}-\d\b`),
		},

		// ─── Generic PII ─────────────────────────────────────────────────
		{
			ID: "email-address", Category: "pii", Severity: SevMedium,
			Keywords: []string{"@"},
			// RFC-5322 simplified: local-part of safe chars, @, domain with TLD ≥2 chars.
			Pattern: mk(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,24}\b`),
			// emailContextRefine drops auto-injected CLI metadata
			// (Claude Code's `# userEmail` block, noreply@…
			// Co-Authored-By templates) while still flagging real
			// emails the user types in their prompt.
			Refine: emailContextRefine,
		},

		// ─── Cards (always-on, Luhn-validated) ───────────────────────────
		{
			ID: "credit-card", Category: "pii-card", Severity: SevHigh,
			// No keyword: we run unconditionally and filter with Luhn,
			// plus a YYYYMMDDHHMMSS reject for log-file timestamps.
			Pattern:  mk(`\b(?:\d[ -]?){12,18}\d\b`),
			Validate: cardPAN,
		},

		// ─── Private IPs (always-on, no useful anchor) ───────────────────
		// Loopback (127.0.0.0/8, ::1) and "localhost" are intentionally NOT
		// matched: they point at the local machine, carry no information about
		// an internal network, and show up constantly in tool output, configs,
		// and docs (masqr's own listener is http://127.0.0.1:<port>).
		{
			ID: "private-ipv4", Category: "internal-ip", Severity: SevLow,
			Pattern: mk(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`),
		},
		{
			ID: "private-ipv6", Category: "internal-ip", Severity: SevLow,
			Keywords: []string{"fc", "fd", "fe80"},
			Pattern:  mk(`\b(?:fc[0-9a-f]{2}:|fd[0-9a-f]{2}:|fe80:)[0-9a-f:]*`),
		},
	}
	return append(rules, presidioRules()...)
}
