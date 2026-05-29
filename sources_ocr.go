//go:build (linux && (amd64 || arm64)) || (darwin && arm64) || (windows && (amd64 || arm64))

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
	"bufio"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ort "github.com/yalue/onnxruntime_go"
)

// logOCRError emits a single log line for an OCR-source error, rate-limited
// to one message per ocrErrorLogInterval to avoid log floods when the same
// failure repeats per crop / per request. Unconditional (debug mode is no
// longer required to surface errors).
var (
	lastOCRErrorLog atomic.Int64 // unix nanos
)

const ocrErrorLogInterval = 30 * time.Second

func logOCRError(format string, args ...any) {
	now := time.Now().UnixNano()
	prev := lastOCRErrorLog.Load()
	if now-prev < int64(ocrErrorLogInterval) {
		return
	}
	if !lastOCRErrorLog.CompareAndSwap(prev, now) {
		return // another goroutine just logged
	}
	log.Printf("ocr: "+format, args...)
}

// Embedded PP-OCRv5 models. Bundling these into the binary makes masqr a
// single self-contained executable: no need to ship the .ocr/ directory
// alongside it. Models and vocab are fed to the ORT session directly as byte
// slices; the platform-specific ONNX runtime shared library is embedded in
// sources_ocr_<goos>_<goarch>.go and exposed via embeddedONNXLib +
// embeddedONNXLibName (the on-disk filename dlopen/LoadLibrary expects).

//go:embed .ocr/det.onnx
var embeddedDetModel []byte

//go:embed .ocr/rec.onnx
var embeddedRecModel []byte

//go:embed .ocr/cls.onnx
var embeddedClsModel []byte

//go:embed .ocr/ppocr_keys_v1.txt
var embeddedVocab []byte

// ocrSource OCRs images embedded in Anthropic content blocks
// (`"media_type": "image/*", "data": "<base64>"`), then feeds the recognized
// text back through the Scanner so secrets/PII embedded in screenshots get
// caught.
//
// Pipeline:
//  1. Find image attachments in the body
//  2. base64-decode → raw image bytes
//  3. Decode PNG/JPEG/GIF → image.Image
//  4. Detection: PP-OCR det model → text-region heatmap → boxes
//  5. Angle classification: PP-OCR cls model → rotate 180°-flipped crops
//  6. Recognition: for each crop, PP-OCR rec model → CTC-decode → text
//  7. Join into one string and rescan with the parent Scanner
//
// ocrWorker owns one full (det, cls, rec) session triple plus their pre-
// allocated input/output tensors. ORT sessions are not goroutine-safe, so
// each in-flight OCR request grabs its own worker out of ocrSource.pool.
type ocrWorker struct {
	detSession *ort.AdvancedSession
	detInput   *ort.Tensor[float32]
	detOutput  *ort.Tensor[float32]
	detW, detH int // current input shape

	clsSession *ort.AdvancedSession
	clsInput   *ort.Tensor[float32]
	clsOutput  *ort.Tensor[float32]

	recSession *ort.AdvancedSession
	recInput   *ort.Tensor[float32]
	recOutput  *ort.Tensor[float32]
	recW       int

	vocab []string // CTC vocabulary, index 0 == blank
}

type ocrSource struct {
	parent  *Scanner
	pool    chan *ocrWorker
	workers []*ocrWorker // owned, all are also in the pool channel
	vocab   []string     // shared, used to size rec output tensors
}

func (o *ocrSource) Name() string { return "ocr" }

// ─── Tunables ───────────────────────────────────────────────────────────
//
// Defaults reflect PaddleOCR's published recommendations for PP-OCRv5 mobile
// models. Promoted to package-level vars (not constants) so contributors can
// override them in tests or downstream forks without touching call sites.
var (
	// detInputH, detInputW are the fixed input tensor dimensions for the
	// detection model. The model itself accepts dynamic shape, but a fixed
	// shape lets us pre-allocate the tensor once. 640×640 is the mobile
	// default; larger values (e.g. 960×960) improve small-text detection
	// at proportional cost.
	detInputH = 640
	detInputW = 640

	// recInputW is the fixed input width for the recognition model. Height
	// is locked at 48 (PP-OCR rec architecture stride /8 → T = W/8
	// timesteps). 320 fits the typical detected crop after aspect-ratio
	// preserving resize; raise it for densely packed lines.
	recInputW = 320

	// detThreshold is the heatmap probability cutoff for the DB-style
	// detector. Lower → catches fainter text but more false positives.
	detThreshold = float32(0.3)

	// detPadX, detPadY are the proportional crop-expansion factors applied
	// to each detected box before cropping. PaddleOCR's reference uses
	// roughly 0.15 horizontally and a more generous vertical pad because
	// heatmap regions are typically tight on Y but loose on X.
	detPadX = 0.15
	detPadY = 0.8

	// clsInputH, clsInputW are the fixed input dimensions for the angle
	// classifier (PP-OCR mobile convention: 48×192).
	clsInputH = 48
	clsInputW = 192

	// clsConfidence is the minimum probability required to trust a 180°
	// rotation decision. Below this, we leave the crop alone — the rec
	// model is reasonably robust to small skew but not to flips.
	clsConfidence = float32(0.9)
)

// Env-var overrides let power users swap in a custom runtime / model files
// without rebuilding. When unset, the embedded binary blobs are used.
var (
	envONNXLib  = "MASQR_ONNX_LIB"
	envOCRDet   = "MASQR_OCR_DET"
	envOCRRec   = "MASQR_OCR_REC"
	envOCRCls   = "MASQR_OCR_CLS"
	envOCRVocab = "MASQR_OCR_VOCAB"
)

var (
	ortInitOnce sync.Once
	ortInitErr  error
)

// initONNXRuntime points the ORT C bindings at a shared library on disk. If
// libPath is empty, the embedded runtime is extracted to a temp file once per
// process and used.
func initONNXRuntime(libPath string) error {
	ortInitOnce.Do(func() {
		if libPath == "" {
			extracted, err := extractEmbeddedLib()
			if err != nil {
				ortInitErr = fmt.Errorf("extract embedded ORT lib: %w", err)
				return
			}
			libPath = extracted
		}
		ort.SetSharedLibraryPath(libPath)
		ortInitErr = ort.InitializeEnvironment()
	})
	return ortInitErr
}

// extractEmbeddedLib writes the embedded libonnxruntime.so.* to a stable
// per-content cache path so dlopen can find it and so we don't leak 22 MB
// into /tmp on every process start. Path is keyed by sha256 of the embed,
// so upgrading the bundled runtime just creates a new cache entry without
// touching the old one. Falls back to MkdirTemp if no cache dir is usable.
func extractEmbeddedLib() (string, error) {
	sum := sha256.Sum256(embeddedONNXLib)
	short := hex.EncodeToString(sum[:8])
	dir, err := cacheDir(short)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, embeddedONNXLibName)

	// Hit: file exists with matching content.
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, embeddedONNXLib) {
		return path, nil
	}

	// Miss: write atomically via a sibling temp file + rename so a concurrent
	// process never observes a half-written .so.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".libonnxruntime.so.*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(embeddedONNXLib); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return "", err
	}
	return path, nil
}

// cacheDir returns the per-content cache directory, preferring
// $XDG_CACHE_HOME, then $HOME/.cache, then $TMPDIR / os.MkdirTemp as a final
// fallback. The short content hash is appended so different bundled-runtime
// versions don't clobber each other.
func cacheDir(short string) (string, error) {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			base = filepath.Join(home, ".cache")
		}
	}
	if base != "" {
		return filepath.Join(base, "masqr", "onnxruntime-"+short), nil
	}
	// No usable cache dir — fall back to a per-process temp dir (the legacy
	// behaviour). This branch is rare (containers with no $HOME, etc.).
	return os.MkdirTemp("", "masqr-ort-"+short+"-*")
}

// ocrPoolSize returns the configured number of OCR workers. Defaults to 2 —
// enough to pipeline one warm request while another finishes. Override via
// MASQR_OCR_WORKERS=<n>. Larger values trade RAM for throughput (each worker
// owns its own ~25 MB session triple).
func ocrPoolSize() int {
	const def = 2
	v := os.Getenv("MASQR_OCR_WORKERS")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return def
	}
	return n
}

func newOCRSource(parent *Scanner) (*ocrSource, error) {
	libPath := os.Getenv(envONNXLib) // empty → use embedded
	if libPath != "" {
		if _, err := os.Stat(libPath); err != nil {
			return nil, fmt.Errorf("OCR component missing: %s", libPath)
		}
	}

	if err := initONNXRuntime(libPath); err != nil {
		return nil, fmt.Errorf("ORT init: %w", err)
	}

	detData, err := readModel(envOCRDet, embeddedDetModel)
	if err != nil {
		return nil, fmt.Errorf("load det model: %w", err)
	}
	recData, err := readModel(envOCRRec, embeddedRecModel)
	if err != nil {
		return nil, fmt.Errorf("load rec model: %w", err)
	}
	clsData, err := readModel(envOCRCls, embeddedClsModel)
	if err != nil {
		return nil, fmt.Errorf("load cls model: %w", err)
	}
	vocab, err := loadVocab(os.Getenv(envOCRVocab))
	if err != nil {
		return nil, fmt.Errorf("load vocab: %w", err)
	}

	n := ocrPoolSize()
	o := &ocrSource{
		parent:  parent,
		vocab:   vocab,
		pool:    make(chan *ocrWorker, n),
		workers: make([]*ocrWorker, 0, n),
	}
	for i := 0; i < n; i++ {
		w, err := newOCRWorker(detData, clsData, recData, vocab)
		if err != nil {
			o.Close()
			return nil, fmt.Errorf("worker %d: %w", i, err)
		}
		o.workers = append(o.workers, w)
		o.pool <- w
	}
	return o, nil
}

// newOCRWorker constructs one (det, cls, rec) session triple plus its
// pre-allocated input/output tensors.
func newOCRWorker(detData, clsData, recData []byte, vocab []string) (*ocrWorker, error) {
	w := &ocrWorker{vocab: vocab}
	if err := w.prepareDetSession(detData, detInputH, detInputW); err != nil {
		return nil, fmt.Errorf("det session: %w", err)
	}
	if err := w.prepareClsSession(clsData); err != nil {
		w.Close()
		return nil, fmt.Errorf("cls session: %w", err)
	}
	if err := w.prepareRecSession(recData, recInputW); err != nil {
		w.Close()
		return nil, fmt.Errorf("rec session: %w", err)
	}
	return w, nil
}

// readModel returns the override-file bytes if the env var points at a real
// file, otherwise the embedded default.
func readModel(envVar string, embedded []byte) ([]byte, error) {
	if path := os.Getenv(envVar); path != "" {
		return os.ReadFile(path)
	}
	return embedded, nil
}

func (o *ocrSource) Close() {
	for _, w := range o.workers {
		w.Close()
	}
}

func (w *ocrWorker) Close() {
	if w.detSession != nil {
		w.detSession.Destroy()
	}
	if w.detInput != nil {
		w.detInput.Destroy()
	}
	if w.detOutput != nil {
		w.detOutput.Destroy()
	}
	if w.clsSession != nil {
		w.clsSession.Destroy()
	}
	if w.clsInput != nil {
		w.clsInput.Destroy()
	}
	if w.clsOutput != nil {
		w.clsOutput.Destroy()
	}
	if w.recSession != nil {
		w.recSession.Destroy()
	}
	if w.recInput != nil {
		w.recInput.Destroy()
	}
	if w.recOutput != nil {
		w.recOutput.Destroy()
	}
}

func (o *ocrWorker) prepareDetSession(modelData []byte, h, w int) error {
	in, err := ort.NewEmptyTensor[float32](ort.NewShape(1, 3, int64(h), int64(w)))
	if err != nil {
		return err
	}
	out, err := ort.NewEmptyTensor[float32](ort.NewShape(1, 1, int64(h), int64(w)))
	if err != nil {
		in.Destroy()
		return err
	}
	sess, err := ort.NewAdvancedSessionWithONNXData(modelData,
		[]string{"x"}, []string{"fetch_name_0"},
		[]ort.Value{in}, []ort.Value{out}, nil)
	if err != nil {
		in.Destroy()
		out.Destroy()
		return err
	}
	o.detSession = sess
	o.detInput = in
	o.detOutput = out
	o.detH, o.detW = h, w
	return nil
}

// prepareClsSession sets up the PP-OCR angle classifier (binary 0°/180°).
// Fixed input shape per PaddleOCR convention: 48x192.
func (o *ocrWorker) prepareClsSession(modelData []byte) error {
	in, err := ort.NewEmptyTensor[float32](ort.NewShape(1, 3, 48, 192))
	if err != nil {
		return err
	}
	out, err := ort.NewEmptyTensor[float32](ort.NewShape(1, 2))
	if err != nil {
		in.Destroy()
		return err
	}
	sess, err := ort.NewAdvancedSessionWithONNXData(modelData,
		[]string{"x"}, []string{"softmax_0.tmp_0"},
		[]ort.Value{in}, []ort.Value{out}, nil)
	if err != nil {
		in.Destroy()
		out.Destroy()
		return err
	}
	o.clsSession = sess
	o.clsInput = in
	o.clsOutput = out
	return nil
}

// classifyAndOrient runs the angle classifier on a crop. If the classifier
// reports 180° rotation with confidence ≥ clsConfidence, the crop is rotated
// 180° before being returned. Below the threshold → leave the crop alone (the
// rec model is reasonably robust to small skew but not to flips).
func (o *ocrWorker) classifyAndOrient(crop image.Image) image.Image {
	bounds := crop.Bounds()
	w := bounds.Dx() * clsInputH / max(1, bounds.Dy())
	if w < 8 {
		w = 8
	}
	if w > clsInputW {
		w = clsInputW
	}
	resized := resizeImage(crop, w, clsInputH)
	padded := image.NewRGBA(image.Rect(0, 0, clsInputW, clsInputH))
	drawInto(padded, resized, 0, 0)

	tensor := imageToTensor(padded, []float32{0.5, 0.5, 0.5}, []float32{0.5, 0.5, 0.5})
	copy(o.clsInput.GetData(), tensor)
	if err := o.clsSession.Run(); err != nil {
		logOCRError("cls inference: %v", err)
		return crop
	}
	probs := o.clsOutput.GetData() // [1, 2] → [P(0°), P(180°)]
	if len(probs) >= 2 && probs[1] > probs[0] && probs[1] >= clsConfidence {
		return rotate180(crop)
	}
	return crop
}

func rotate180(src image.Image) image.Image {
	sb := src.Bounds()
	w, h := sb.Dx(), sb.Dy()
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			dst.Set(w-1-x, h-1-y, src.At(sb.Min.X+x, sb.Min.Y+y))
		}
	}
	return dst
}

func (o *ocrWorker) prepareRecSession(modelData []byte, w int) error {
	// H=48 fixed, W variable; PP-OCRv5 rec stride is /8 → T = W/8 timesteps.
	in, err := ort.NewEmptyTensor[float32](ort.NewShape(1, 3, 48, int64(w)))
	if err != nil {
		return err
	}
	t := int64(w / 8)
	if t < 1 {
		t = 1
	}
	out, err := ort.NewEmptyTensor[float32](ort.NewShape(1, t, int64(len(o.vocab))))
	if err != nil {
		in.Destroy()
		return err
	}
	sess, err := ort.NewAdvancedSessionWithONNXData(modelData,
		[]string{"x"}, []string{"fetch_name_0"},
		[]ort.Value{in}, []ort.Value{out}, nil)
	if err != nil {
		in.Destroy()
		out.Destroy()
		return err
	}
	o.recSession = sess
	o.recInput = in
	o.recOutput = out
	o.recW = w
	return nil
}

// ─── Scan entry point ───────────────────────────────────────────────────

// imageDataPatterns extract inline base64 image payloads from the JSON body
// of each supported LLM provider's wire format. Each pattern's first capture
// group is the base64 data string. Add a new entry to support more providers.
var imageDataPatterns = []*regexp.Regexp{
	// Anthropic Messages API:
	//   {"type":"image","source":{"type":"base64","media_type":"image/png","data":"…"}}
	regexp.MustCompile(`"media_type"\s*:\s*"image/[a-z0-9.+-]+"\s*,\s*"data"\s*:\s*"([A-Za-z0-9+/=]+)"`),

	// Google Gemini API (generateContent):
	//   {"inline_data":{"mime_type":"image/png","data":"…"}}
	regexp.MustCompile(`"mime_type"\s*:\s*"image/[a-z0-9.+-]+"\s*,\s*"data"\s*:\s*"([A-Za-z0-9+/=]+)"`),

	// OpenAI Chat Completions vision:
	//   {"type":"image_url","image_url":{"url":"data:image/png;base64,…"}}
	regexp.MustCompile(`"url"\s*:\s*"data:image/[a-z0-9.+-]+;base64,([A-Za-z0-9+/=]+)"`),
}

func (o *ocrSource) Scan(body []byte) []Match {
	type hit struct {
		dataStart, dataEnd int
		blockStart         int // byte offset of the surrounding JSON block, for re-anchoring
	}
	var hits []hit
	for _, pat := range imageDataPatterns {
		for _, m := range pat.FindAllSubmatchIndex(body, -1) {
			hits = append(hits, hit{dataStart: m[2], dataEnd: m[3], blockStart: m[0]})
		}
	}
	if len(hits) == 0 {
		return nil
	}
	var out []Match
	for _, h := range hits {
		raw, err := base64.StdEncoding.DecodeString(string(body[h.dataStart:h.dataEnd]))
		if err != nil {
			continue
		}
		text, err := o.recognize(raw)
		if err != nil || strings.TrimSpace(text) == "" {
			continue
		}
		// Rescan the OCR'd text via the parent Scanner (without re-entering
		// the OCR source, which would loop on the same image bytes).
		nested := o.parent.scanWithoutOCR([]byte(text))
		for _, m := range nested {
			m.RuleID += "/from-image"
			m.Offset = h.blockStart // re-anchor to the outer image-block position
			out = append(out, m)
		}
	}
	return out
}

// ─── Inference ──────────────────────────────────────────────────────────

func (o *ocrSource) recognize(imageBytes []byte) (string, error) {
	img, _, err := image.Decode(bytes.NewReader(imageBytes))
	if err != nil {
		return "", fmt.Errorf("image decode: %w", err)
	}
	w := <-o.pool
	defer func() { o.pool <- w }()
	return w.recognize(img)
}

func (o *ocrWorker) recognize(img image.Image) (string, error) {
	boxes, err := o.detect(img)
	if err != nil {
		return "", fmt.Errorf("detect: %w", err)
	}
	if os.Getenv("MASQR_OCR_DEBUG") == "1" {
		log.Printf("ocr: image %dx%d -> %d boxes", img.Bounds().Dx(), img.Bounds().Dy(), len(boxes))
	}
	if len(boxes) == 0 {
		// Fall back: try OCR on the whole image as a single line.
		oriented := o.classifyAndOrient(img)
		text, _ := o.recognizeCrop(oriented)
		if os.Getenv("MASQR_OCR_DEBUG") == "1" {
			log.Printf("ocr: no boxes, whole-image rec → %q", text)
		}
		return text, nil
	}

	// Sort boxes top-to-bottom, then left-to-right.
	sort.Slice(boxes, func(i, j int) bool {
		if math.Abs(float64(boxes[i].MinY-boxes[j].MinY)) > 10 {
			return boxes[i].MinY < boxes[j].MinY
		}
		return boxes[i].MinX < boxes[j].MinX
	})

	var lines []string
	for i, b := range boxes {
		crop := o.classifyAndOrient(cropImage(img, b))
		txt, err := o.recognizeCrop(crop)
		if os.Getenv("MASQR_OCR_DEBUG") == "1" {
			log.Printf("ocr: box %d %+v -> %q (err=%v)", i, b, txt, err)
		}
		if err != nil {
			logOCRError("rec box %d: %v", i, err)
			continue
		}
		if strings.TrimSpace(txt) == "" {
			continue
		}
		lines = append(lines, strings.TrimSpace(txt))
	}
	return strings.Join(lines, "\n"), nil
}

// detect runs the PP-OCRv5 detection model and returns axis-aligned bounding
// boxes (in original image pixel coords) of every connected region whose
// heatmap probability exceeds the threshold.
//
// PaddleOCR detection expects the image resized so the longest side is ≤ 960
// (we use 640 for our fixed tensor) with the aspect ratio preserved, then
// padded with zeros to the full tensor dimensions.
func (o *ocrWorker) detect(img image.Image) ([]bbox, error) {
	bounds := img.Bounds()
	origW, origH := bounds.Dx(), bounds.Dy()

	// Aspect-preserving fit within (detW, detH).
	scale := math.Min(float64(o.detW)/float64(origW), float64(o.detH)/float64(origH))
	fitW := int(math.Round(float64(origW) * scale))
	fitH := int(math.Round(float64(origH) * scale))
	if fitW < 1 {
		fitW = 1
	}
	if fitH < 1 {
		fitH = 1
	}
	resized := resizeImage(img, fitW, fitH)
	padded := image.NewRGBA(image.Rect(0, 0, o.detW, o.detH))
	drawInto(padded, resized, 0, 0)

	tensor := imageToTensor(padded, []float32{0.485, 0.456, 0.406}, []float32{0.229, 0.224, 0.225})
	copy(o.detInput.GetData(), tensor)

	if err := o.detSession.Run(); err != nil {
		return nil, err
	}

	heatmap := o.detOutput.GetData()
	// Un-projection: heatmap coords → resized coords → original coords.
	// Since we padded (not stretched), invScale = 1/scale converts back.
	invScale := 1.0 / scale
	// Restrict the search to the un-padded region.
	mask := make([]bool, o.detW*o.detH)
	for i, p := range heatmap {
		mask[i] = p > detThreshold
	}
	components := connectedComponents(mask, o.detW, o.detH)

	boxes := make([]bbox, 0, len(components))
	for _, c := range components {
		if c.MaxX-c.MinX < 3 || c.MaxY-c.MinY < 3 {
			continue
		}
		// Project heatmap coords back to original image coords.
		cx0 := float64(c.MinX) * invScale
		cy0 := float64(c.MinY) * invScale
		cx1 := float64(c.MaxX) * invScale
		cy1 := float64(c.MaxY) * invScale
		// PaddleOCR-style expansion: pad each side by detPadX / detPadY of
		// box size so the crop captures full glyph ascenders/descenders.
		padX := (cx1 - cx0) * detPadX
		padY := (cy1 - cy0) * detPadY
		minX := int(math.Max(0, cx0-padX))
		minY := int(math.Max(0, cy0-padY))
		maxX := int(math.Min(float64(origW), cx1+padX))
		maxY := int(math.Min(float64(origH), cy1+padY))
		boxes = append(boxes, bbox{minX, minY, maxX, maxY})
	}
	return boxes, nil
}

func (o *ocrWorker) recognizeCrop(crop image.Image) (string, error) {
	const H = 48
	bounds := crop.Bounds()
	w := bounds.Dx() * H / max(1, bounds.Dy())
	if w < 8 {
		w = 8
	}
	if w > o.recW {
		w = o.recW
	}
	resized := resizeImage(crop, w, H)

	// Pad to (H, recW) with zeros so the tensor shape stays fixed.
	padded := image.NewRGBA(image.Rect(0, 0, o.recW, H))
	drawInto(padded, resized, 0, 0)

	tensor := imageToTensor(padded, []float32{0.5, 0.5, 0.5}, []float32{0.5, 0.5, 0.5})
	copy(o.recInput.GetData(), tensor)

	if err := o.recSession.Run(); err != nil {
		return "", err
	}
	logits := o.recOutput.GetData() // [1, T, V]
	shape := o.recOutput.GetShape()
	t, v := int(shape[1]), int(shape[2])
	return ctcDecode(logits, t, v, o.vocab), nil
}

// ─── Helpers ────────────────────────────────────────────────────────────

type bbox struct{ MinX, MinY, MaxX, MaxY int }

// loadVocab reads a PP-OCR keys file. If path is empty, the embedded vocab is
// used; otherwise the override file is read from disk.
func loadVocab(path string) ([]string, error) {
	var src []byte
	if path == "" {
		src = embeddedVocab
	} else {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		src = b
	}
	vocab := []string{""} // index 0 is CTC blank
	sc := bufio.NewScanner(bytes.NewReader(src))
	for sc.Scan() {
		vocab = append(vocab, sc.Text())
	}
	vocab = append(vocab, " ") // PP-OCR convention: trailing space token
	return vocab, sc.Err()
}

// imageToTensor flattens an image to NCHW float32 with per-channel mean/std
// normalization. R, G, B order.
func imageToTensor(img image.Image, mean, std []float32) []float32 {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	t := make([]float32, 3*h*w)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r, g, bl, _ := img.At(x+b.Min.X, y+b.Min.Y).RGBA()
			rf := float32(r>>8) / 255.0
			gf := float32(g>>8) / 255.0
			bf := float32(bl>>8) / 255.0
			t[0*h*w+y*w+x] = (rf - mean[0]) / std[0]
			t[1*h*w+y*w+x] = (gf - mean[1]) / std[1]
			t[2*h*w+y*w+x] = (bf - mean[2]) / std[2]
		}
	}
	return t
}

// resizeImage uses nearest-neighbor. Good enough for OCR preprocessing.
func resizeImage(src image.Image, w, h int) image.Image {
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	sb := src.Bounds()
	sw, sh := sb.Dx(), sb.Dy()
	for y := 0; y < h; y++ {
		sy := y * sh / h
		for x := 0; x < w; x++ {
			sx := x * sw / w
			dst.Set(x, y, src.At(sb.Min.X+sx, sb.Min.Y+sy))
		}
	}
	return dst
}

func drawInto(dst *image.RGBA, src image.Image, x0, y0 int) {
	sb := src.Bounds()
	for y := 0; y < sb.Dy(); y++ {
		for x := 0; x < sb.Dx(); x++ {
			dst.Set(x0+x, y0+y, src.At(sb.Min.X+x, sb.Min.Y+y))
		}
	}
}

func cropImage(src image.Image, b bbox) image.Image {
	sb := src.Bounds()
	r := image.Rect(b.MinX+sb.Min.X, b.MinY+sb.Min.Y, b.MaxX+sb.Min.X, b.MaxY+sb.Min.Y)
	r = r.Intersect(sb)
	dst := image.NewRGBA(image.Rect(0, 0, r.Dx(), r.Dy()))
	drawInto(dst, src, -r.Min.X, -r.Min.Y)
	return dst
}

// connectedComponents returns axis-aligned bounding boxes of every blob in a
// binary mask. Two-pass union-find over 4-connected pixels.
func connectedComponents(mask []bool, w, h int) []bbox {
	labels := make([]int, len(mask))
	parent := []int{0}
	find := func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
	}
	next := 1
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			i := y*w + x
			if !mask[i] {
				continue
			}
			var n, wL int
			if y > 0 {
				n = labels[i-w]
			}
			if x > 0 {
				wL = labels[i-1]
			}
			switch {
			case n == 0 && wL == 0:
				parent = append(parent, next)
				labels[i] = next
				next++
			case n != 0 && wL == 0:
				labels[i] = n
			case n == 0 && wL != 0:
				labels[i] = wL
			default:
				labels[i] = n
				union(n, wL)
			}
		}
	}
	// Reduce labels to roots and collect bboxes.
	boxes := map[int]*bbox{}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			i := y*w + x
			if labels[i] == 0 {
				continue
			}
			r := find(labels[i])
			b, ok := boxes[r]
			if !ok {
				boxes[r] = &bbox{x, y, x, y}
				continue
			}
			if x < b.MinX {
				b.MinX = x
			}
			if y < b.MinY {
				b.MinY = y
			}
			if x > b.MaxX {
				b.MaxX = x
			}
			if y > b.MaxY {
				b.MaxY = y
			}
		}
	}
	out := make([]bbox, 0, len(boxes))
	for _, b := range boxes {
		out = append(out, *b)
	}
	return out
}

// ctcDecode collapses a [T, V] softmax sequence into a string by greedy argmax
// + run-length collapse + blank removal.
func ctcDecode(logits []float32, t, v int, vocab []string) string {
	var sb strings.Builder
	prev := -1
	for i := 0; i < t; i++ {
		best, bestP := 0, float32(-1)
		for j := 0; j < v; j++ {
			p := logits[i*v+j]
			if p > bestP {
				bestP = p
				best = j
			}
		}
		if best != 0 && best != prev && best < len(vocab) {
			sb.WriteString(vocab[best])
		}
		prev = best
	}
	return sb.String()
}

// Reused by Scanner.attachExternalSources.
func (s *Scanner) maybeAttachOCR() {
	if os.Getenv("MASQR_OCR") != "1" {
		return
	}
	o, err := newOCRSource(s)
	if err != nil {
		log.Printf("scanner: OCR source disabled: %v", err)
		return
	}
	s.sources = append(s.sources, o)
	log.Printf("scanner: OCR source enabled (vocab=%d entries)", len(o.vocab))
}

// scanWithoutOCR runs the same logic as Scan but skips the OCR source — used
// by the OCR source to rescan recognized text without infinite-looping back
// into itself.
func (s *Scanner) scanWithoutOCR(body []byte) []Match {
	saved := s.sources
	filtered := make([]ScanSource, 0, len(saved))
	for _, src := range saved {
		if src.Name() != "ocr" {
			filtered = append(filtered, src)
		}
	}
	s.sources = filtered
	defer func() { s.sources = saved }()
	return s.scanRecursive(body, 1)
}
