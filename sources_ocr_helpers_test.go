//go:build linux && amd64

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
	"image"
	"image/color"
	"os"
	"reflect"
	"testing"
)

func TestLoadVocabEmbedded(t *testing.T) {
	v, err := loadVocab("") // "" → embedded vocab
	if err != nil {
		t.Fatalf("loadVocab: %v", err)
	}
	if len(v) < 100 {
		t.Fatalf("vocab too small: %d (expected >100)", len(v))
	}
	if v[0] != "" {
		t.Errorf("vocab[0] should be CTC blank (\"\"), got %q", v[0])
	}
	if v[len(v)-1] != " " {
		t.Errorf("vocab[last] should be trailing-space token, got %q", v[len(v)-1])
	}
	// Spot-check a couple of well-known PP-OCRv5 entries we expect to be there.
	seen := map[string]bool{}
	for _, s := range v {
		seen[s] = true
	}
	for _, want := range []string{"0", "a", "A", "中"} {
		if !seen[want] {
			t.Errorf("vocab missing well-known glyph %q", want)
		}
	}
}

func TestCTCDecode(t *testing.T) {
	// Build a tiny vocab: blank, "a", "b", "c". V=4, T=6.
	vocab := []string{"", "a", "b", "c"}
	// Pseudo-logits: at each t pick a winning class. Sequence aabbc → after
	// collapse (blank=0, no duplicate run) → "abc".
	//   t0: a (idx 1)
	//   t1: a (idx 1)   -- duplicate of t0 → suppressed
	//   t2: blank (0)   -- resets the duplicate filter
	//   t3: b (idx 2)
	//   t4: b (idx 2)   -- duplicate of t3 → suppressed
	//   t5: c (idx 3)
	winners := []int{1, 1, 0, 2, 2, 3}
	v := 4
	logits := make([]float32, len(winners)*v)
	for ti, w := range winners {
		for j := 0; j < v; j++ {
			if j == w {
				logits[ti*v+j] = 1.0
			} else {
				logits[ti*v+j] = 0.0
			}
		}
	}
	got := ctcDecode(logits, len(winners), v, vocab)
	if got != "abc" {
		t.Fatalf("ctcDecode = %q, want %q", got, "abc")
	}
}

func TestCTCDecodeAllBlank(t *testing.T) {
	vocab := []string{"", "a"}
	logits := []float32{1, 0, 1, 0, 1, 0} // T=3, V=2, always blank
	if got := ctcDecode(logits, 3, 2, vocab); got != "" {
		t.Errorf("all-blank decode = %q, want empty", got)
	}
}

func TestImageToTensor(t *testing.T) {
	// 2x2 RGB image — red (255,0,0), green (0,255,0), blue (0,0,255), white.
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{255, 0, 0, 255})
	img.Set(1, 0, color.RGBA{0, 255, 0, 255})
	img.Set(0, 1, color.RGBA{0, 0, 255, 255})
	img.Set(1, 1, color.RGBA{255, 255, 255, 255})
	// Identity normalization → just channel-major float32 in [0,1].
	mean := []float32{0, 0, 0}
	std := []float32{1, 1, 1}
	got := imageToTensor(img, mean, std)
	if len(got) != 3*2*2 {
		t.Fatalf("len(tensor) = %d, want 12", len(got))
	}
	// R-plane: red=1, green=0, blue=0, white=1 → [1,0,0,1] in row-major order
	wantR := []float32{1, 0, 0, 1}
	if !floatSliceApprox(got[0:4], wantR, 0.01) {
		t.Errorf("R plane = %v, want %v", got[0:4], wantR)
	}
	// G-plane: red=0, green=1, blue=0, white=1 → [0,1,0,1]
	wantG := []float32{0, 1, 0, 1}
	if !floatSliceApprox(got[4:8], wantG, 0.01) {
		t.Errorf("G plane = %v, want %v", got[4:8], wantG)
	}
	// B-plane: red=0, green=0, blue=1, white=1 → [0,0,1,1]
	wantB := []float32{0, 0, 1, 1}
	if !floatSliceApprox(got[8:12], wantB, 0.01) {
		t.Errorf("B plane = %v, want %v", got[8:12], wantB)
	}
}

func TestImageToTensorNormalization(t *testing.T) {
	// 1x1 mid-gray image; with mean=0.5, std=0.5 the result should be ~0.
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{128, 128, 128, 255})
	got := imageToTensor(img, []float32{0.5, 0.5, 0.5}, []float32{0.5, 0.5, 0.5})
	for i, v := range got {
		if v < -0.02 || v > 0.02 {
			t.Errorf("normalized gray pixel[%d] = %f, want ~0", i, v)
		}
	}
}

func TestRotate180(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 2, 1))
	src.Set(0, 0, color.RGBA{255, 0, 0, 255}) // red on left
	src.Set(1, 0, color.RGBA{0, 0, 255, 255}) // blue on right

	rot := rotate180(src)
	r, _, _, _ := rot.At(0, 0).RGBA()
	if r>>8 != 0 { // expected blue (R=0)
		t.Errorf("rotated[0,0] R-channel = %d, expected 0 (was originally blue)", r>>8)
	}
	r2, _, _, _ := rot.At(1, 0).RGBA()
	if r2>>8 != 255 { // expected red (R=255)
		t.Errorf("rotated[1,0] R-channel = %d, expected 255 (was originally red)", r2>>8)
	}
}

func TestConnectedComponents(t *testing.T) {
	// 4x3 mask, two distinct blobs:
	//   1 1 0 0
	//   0 0 0 1
	//   0 0 0 1
	w, h := 4, 3
	mask := []bool{
		true, true, false, false,
		false, false, false, true,
		false, false, false, true,
	}
	got := connectedComponents(mask, w, h)
	if len(got) != 2 {
		t.Fatalf("expected 2 components, got %d: %+v", len(got), got)
	}
	// Normalize order for stable assertion.
	boxesByMinX := map[int]bbox{}
	for _, b := range got {
		boxesByMinX[b.MinX] = b
	}
	if b, ok := boxesByMinX[0]; !ok || b != (bbox{0, 0, 1, 0}) {
		t.Errorf("left blob = %+v, want {0,0,1,0}", b)
	}
	if b, ok := boxesByMinX[3]; !ok || b != (bbox{3, 1, 3, 2}) {
		t.Errorf("right blob = %+v, want {3,1,3,2}", b)
	}
}

func TestConnectedComponentsEmptyMask(t *testing.T) {
	mask := make([]bool, 16)
	got := connectedComponents(mask, 4, 4)
	if !reflect.DeepEqual(got, []bbox{}) && len(got) != 0 {
		t.Errorf("expected empty result for all-false mask, got %+v", got)
	}
}

// TestOCRWorkerRoundTrip exercises the full pool path: take a worker, return
// it, take it again. Without crashing or panicking, pool semantics are sound.
// Skipped unless MASQR_OCR_TEST_IMAGE is set so the embedded models actually
// run (avoids the 5+ second cold-start cost on every test).
func TestOCRWorkerRoundTrip(t *testing.T) {
	if os.Getenv("MASQR_OCR_TEST_IMAGE") == "" {
		t.Skip("set MASQR_OCR_TEST_IMAGE to run pool round-trip test")
	}
	parent := NewScanner(nil)
	o, err := newOCRSource(parent)
	if err != nil {
		t.Fatalf("newOCRSource: %v", err)
	}
	defer o.Close()
	if cap(o.pool) < 1 || len(o.workers) < 1 {
		t.Fatalf("pool not populated: cap=%d workers=%d", cap(o.pool), len(o.workers))
	}
	for i := 0; i < 2; i++ {
		w := <-o.pool
		if w == nil {
			t.Fatalf("got nil worker on iteration %d", i)
		}
		o.pool <- w
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────

func floatSliceApprox(got, want []float32, tol float32) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		d := got[i] - want[i]
		if d < 0 {
			d = -d
		}
		if d > tol {
			return false
		}
	}
	return true
}
