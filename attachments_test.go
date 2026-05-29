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

import (
	"strings"
	"testing"
)

func TestAttachmentInlineImage(t *testing.T) {
	s := NewScanner(defaultRules())
	body := []byte(`{
		"model": "claude-opus-4-7",
		"messages": [{"role":"user","content":[
			{"type":"text","text":"what's this?"},
			{"type":"image","source":{"type":"base64","media_type":"image/jpeg","data":"/9j/4AAQSkZ...lots..."}}
		]}]
	}`)
	matches := s.Scan(body)
	want := "attachment-image-inline"
	if !hasRule(matches, want) {
		t.Errorf("expected %s, got %v", want, ruleIDs(matches))
	}
}

func TestAttachmentInlinePDF(t *testing.T) {
	s := NewScanner(defaultRules())
	body := []byte(`{"messages":[{"content":[{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"JVBERi0xLjQK..."}}]}]}`)
	if !hasRule(s.Scan(body), "attachment-pdf-inline") {
		t.Errorf("expected attachment-pdf-inline")
	}
}

func TestAttachmentInlineAudio(t *testing.T) {
	s := NewScanner(defaultRules())
	body := []byte(`{"content":[{"source":{"media_type":"audio/mpeg","data":"..."}}]}`)
	if !hasRule(s.Scan(body), "attachment-audio-inline") {
		t.Errorf("expected attachment-audio-inline")
	}
}

func TestAttachmentInlineVideo(t *testing.T) {
	s := NewScanner(defaultRules())
	body := []byte(`{"content":[{"source":{"media_type":"video/mp4","data":"..."}}]}`)
	if !hasRule(s.Scan(body), "attachment-video-inline") {
		t.Errorf("expected attachment-video-inline")
	}
}

func TestAttachmentFileReference(t *testing.T) {
	s := NewScanner(defaultRules())
	body := []byte(`{"content":[{"type":"image","source":{"type":"file","file_id":"file_abc123def456ghi789"}}]}`)
	if !hasRule(s.Scan(body), "attachment-file-reference") {
		t.Errorf("expected attachment-file-reference, got %v", ruleIDs(s.Scan(body)))
	}
}

func TestAttachmentURLSource(t *testing.T) {
	s := NewScanner(defaultRules())
	body := []byte(`{"content":[{"type":"image","source":{"type":"url","url":"https://example.com/photo.jpg"}}]}`)
	matches := s.Scan(body)
	if !hasRule(matches, "attachment-url-source") {
		t.Errorf("expected attachment-url-source, got %v", ruleIDs(matches))
	}
}

func TestAttachmentDocumentBlock(t *testing.T) {
	s := NewScanner(defaultRules())
	body := []byte(`{"content":[{"type":"document","source":{"type":"text","data":"..."}}]}`)
	if !hasRule(s.Scan(body), "attachment-document-block") {
		t.Errorf("expected attachment-document-block")
	}
}

func TestAttachmentMultipleInOneBody(t *testing.T) {
	s := NewScanner(defaultRules())
	body := []byte(`{"content":[
		{"type":"image","source":{"media_type":"image/png","data":"..."}},
		{"type":"document","source":{"media_type":"application/pdf","data":"..."}},
		{"type":"image","source":{"type":"file","file_id":"file_xyz12345"}}
	]}`)
	matches := s.Scan(body)
	want := []string{"attachment-image-inline", "attachment-pdf-inline", "attachment-file-reference"}
	for _, w := range want {
		if !hasRule(matches, w) {
			t.Errorf("missing %s in %v", w, ruleIDs(matches))
		}
	}
}

func TestNoAttachmentInPlainText(t *testing.T) {
	s := NewScanner(defaultRules())
	body := []byte(`{"messages":[{"role":"user","content":"please review the code and suggest improvements"}]}`)
	for _, m := range s.Scan(body) {
		if strings.HasPrefix(m.RuleID, "attachment-") {
			t.Errorf("plain-text prompt incorrectly flagged: %+v", m)
		}
	}
}

func hasRule(ms []Match, ruleID string) bool {
	for _, m := range ms {
		if m.RuleID == ruleID {
			return true
		}
	}
	return false
}
