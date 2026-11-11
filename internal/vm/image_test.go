package vm

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"os/exec"
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
