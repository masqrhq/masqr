package main

import "testing"

// Regression checks for swarm findings after scanner patches.
func TestFindingFA_a0a9820b1f7d_UnicodeGCP(t *testing.T) {
	prompt := `Our staging Maps widget 403s after we locked down the GCP project. In Slack I pasted GOOGLE_MAPS_API_KEY="\u0041\u0049\u007a\u0061\u0053\u0079\u0041\u0061\u0062\u0063\u0064\u0065\u0066\u0067\u0068\u0069\u006a\u006b\u006c\u006d\u006e\u006f\u0070\u0071\u0072\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007a\u0031\u0032\u0033\u0034\u0035\u0036" to unblock QA — can you walk me through moving this to Secret Manager so I stop leaking it in chat?`
	assertRule(t, []byte(prompt), "gcp-api-key")
}

func TestFindingFP_usSSN_BenignCode(t *testing.T) {
	samples := []string{
		`/**
 * Module dependencies.
 */

var express = require('../..');
var path = require('node:path');
var app = express();
var logger = require('morgan');
var cooki`,
		`if err != nil {
		panic(err)
	}
	*((*time.Time)(ptr)) = t
}

// endregion

// region *Time Extension

var (
	timePointerType         = reflect2.TypeOfPtr((**tim`,
		`// Copyright 2022 Gin Core Team. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

p`,
	}
	s := NewScanner(defaultRules())
	for i, sample := range samples {
		for _, m := range s.Scan([]byte(sample)) {
			if m.RuleID == "us-ssn" {
				t.Fatalf("sample %d: unexpected us-ssn on benign code", i)
			}
		}
	}
}

func assertRule(t *testing.T, body []byte, want string) {
	t.Helper()
	s := NewScanner(defaultRules())
	for _, m := range s.Scan(body) {
		if m.RuleID == want || m.RuleID == want+"/unicode-decoded" || m.RuleID == want+"/base64-decoded" {
			return
		}
	}
	ids := make([]string, 0, 8)
	for _, m := range s.Scan(body) {
		ids = append(ids, m.RuleID)
	}
	t.Fatalf("expected %q, got %v", want, ids)
}
