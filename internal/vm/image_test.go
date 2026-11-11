package vm

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

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
