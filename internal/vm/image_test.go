package vm

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ulikunitz/xz"

	"hat/internal/config"
)

func TestImportAndClone(t *testing.T) {
	t.Setenv(config.EnvHome, t.TempDir())
	// 1 MiB disk: data, a zero hole, data.
	disk := make([]byte, 1<<20)
	copy(disk, "BOOT")
	copy(disk[900<<10:], "TAIL")
	var buf bytes.Buffer
	xw, _ := xz.NewWriter(&buf)
	tw := tar.NewWriter(xw)
	tw.WriteHeader(&tar.Header{Name: "disk.raw", Mode: 0o644, Size: int64(len(disk)), Typeflag: tar.TypeReg})
	tw.Write(disk)
	tw.Close()
	xw.Close()
	arc := filepath.Join(t.TempDir(), "img.tar.xz")
	os.WriteFile(arc, buf.Bytes(), 0o600)
	if err := ImportImage("debian-13", arc, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	raw, _ := ImagePath("debian-13")
	got, _ := os.ReadFile(raw)
	if !bytes.Equal(got, disk) {
		t.Fatal("extracted image differs")
	}
	dst := filepath.Join(t.TempDir(), "disk.raw")
	if err := CloneDisk(raw, dst, 4); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(dst)
	if st.Size() != 4<<30 {
		t.Fatalf("size %d", st.Size())
	}
	f, _ := os.Open(dst)
	head := make([]byte, 4)
	f.Read(head)
	f.Close()
	if string(head) != "BOOT" {
		t.Fatal("clone content wrong")
	}
	if err := CloneDisk(raw, dst, 4); err == nil {
		t.Fatal("overwrote existing disk")
	}
}

// Debian's official archive stores disk.raw as a GNU sparse file (type 'S').
func TestImportGNUSparse(t *testing.T) {
	if _, err := exec.LookPath("tar"); err != nil {
		t.Skip("tar not available")
	}
	if out, _ := exec.Command("tar", "--version").Output(); !bytes.Contains(out, []byte("GNU tar")) {
		t.Skip("needs GNU tar to build a sparse archive")
	}
	t.Setenv(config.EnvHome, t.TempDir())
	src := t.TempDir()
	disk := filepath.Join(src, "disk.raw")
	f, _ := os.Create(disk)
	f.WriteAt([]byte("BOOTSECTOR"), 0)
	f.WriteAt([]byte("MIDDLE"), 64<<20)
	f.Truncate(256 << 20) // 256 MiB, mostly holes
	f.Close()
	tarPath := filepath.Join(t.TempDir(), "img.tar")
	if out, err := exec.Command("tar", "--sparse", "--format=gnu", "-C", src, "-cf", tarPath, "disk.raw").CombinedOutput(); err != nil {
		t.Fatalf("tar: %v %s", err, out)
	}
	// Confirm the fixture really is a GNU sparse entry, like Debian's.
	tf, _ := os.Open(tarPath)
	hdr, err := tar.NewReader(tf).Next()
	tf.Close()
	if err != nil || hdr.Typeflag != tar.TypeGNUSparse {
		t.Fatalf("fixture is not GNU sparse: %v %q", err, hdr.Typeflag)
	}
	raw, _ := os.ReadFile(tarPath)
	var buf bytes.Buffer
	xw, _ := xz.NewWriter(&buf)
	xw.Write(raw)
	xw.Close()
	arc := filepath.Join(t.TempDir(), "img.tar.xz")
	os.WriteFile(arc, buf.Bytes(), 0o600)

	if err := ImportImage("debian-13", arc, io.Discard); err != nil {
		t.Fatal(err)
	}
	out, _ := ImagePath("debian-13")
	st, _ := os.Stat(out)
	if st.Size() != 256<<20 {
		t.Fatalf("size %d", st.Size())
	}
	g, _ := os.Open(out)
	defer g.Close()
	b := make([]byte, 10)
	g.ReadAt(b, 0)
	m := make([]byte, 6)
	g.ReadAt(m, 64<<20)
	if string(b) != "BOOTSECTOR" || string(m) != "MIDDLE" {
		t.Fatalf("content wrong: %q %q", b, m)
	}
	// The output stays sparse (allocated blocks far below the logical size).
	if blocks := allocatedBytes(st); blocks > 16<<20 {
		t.Fatalf("output not sparse: %d bytes allocated", blocks)
	}
}

// Reported from the macOS retest: the first image download died with
// "unexpected EOF" around 64 MiB. Downloads now resume with Range requests.
func TestDownloadResumesAfterInterruption(t *testing.T) {
	payload := make([]byte, 3<<20)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	sum := sha512.Sum512(payload)
	want := hex.EncodeToString(sum[:])
	var cuts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cuts.Load() < 2 {
			// Send part of the remaining body, then drop the connection.
			cuts.Add(1)
			start := 0
			if rg := r.Header.Get("Range"); rg != "" {
				fmt.Sscanf(rg, "bytes=%d-", &start)
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(payload)-1, len(payload)))
				w.Header().Set("Content-Length", strconv.Itoa(len(payload)-start))
				w.WriteHeader(http.StatusPartialContent)
			} else {
				w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
			}
			w.Write(payload[start : start+(1<<20)])
			w.(http.Flusher).Flush()
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		http.ServeContent(w, r, "img", time.Time{}, bytes.NewReader(payload))
	}))
	defer srv.Close()
	old := downloadAttempts
	downloadAttempts = 4
	defer func() { downloadAttempts = old }()
	dst := filepath.Join(t.TempDir(), "img.part")
	start := time.Now()
	if err := download(context.Background(), srv.Client(), srv.URL, dst, want, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, payload) {
		t.Fatal("resumed download differs")
	}
	if time.Since(start) > 20*time.Second {
		t.Fatal("too slow")
	}
	// A corrupt result is rejected and removed.
	os.WriteFile(dst, []byte("garbage"), 0o600)
	cuts.Store(10)
	if err := download(context.Background(), srv.Client(), srv.URL, dst, strings.Repeat("0", 128), io.Discard); err == nil {
		t.Fatal("checksum mismatch accepted")
	}
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("bad download not removed")
	}
}
