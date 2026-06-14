package main

import "testing"

func TestUnicodeEscapeDecodeRescan(t *testing.T) {
	prompt := `GOOGLE_MAPS_API_KEY="\u0041\u0049\u007a\u0061\u0053\u0079\u0041\u0061\u0062\u0063\u0064\u0065\u0066\u0067\u0068\u0069\u006a\u006b\u006c\u006d\u006e\u006f\u0070\u0071\u0072\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007a\u0031\u0032\u0033\u0034\u0035\u0036"`
	body := []byte(prompt)
	s := NewScanner(defaultRules())
	matches := s.Scan(body)
	found := false
	for _, m := range matches {
		if m.RuleID == "gcp-api-key/unicode-decoded" || m.RuleID == "gcp-api-key" {
			found = true
			break
		}
	}
	if !found {
		ids := make([]string, 0, len(matches))
		for _, m := range matches {
			ids = append(ids, m.RuleID)
		}
		t.Fatalf("expected gcp-api-key via unicode decode, got %v", ids)
	}
}

func TestUSSSNKeywordGate(t *testing.T) {
	s := newDigitIDSource()
	// bare 9-digit run in code — should not fire without label
	benign := []byte("timePointerType = reflect2.TypeOfPtr((**tim")
	if ms := s.Scan(benign); len(ms) != 0 {
		t.Fatalf("unexpected digit-id matches on benign code: %v", ms)
	}
	// labelled SSN still fires
	labeled := []byte("SSN 219-12-3456 for tax docs")
	ms := s.Scan(labeled)
	found := false
	for _, m := range ms {
		if m.RuleID == "us-ssn" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected us-ssn on labelled SSN")
	}
}
