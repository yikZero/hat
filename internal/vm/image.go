package vm

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ulikunitz/xz"

	"hat/internal/config"
)

// ImageSpec describes a downloadable guest image.
type ImageSpec struct {
	Name    string
	URL     string // .tar.xz containing disk.raw
	SumsURL string // SHA512SUMS listing
	File    string // file name inside SumsURL
}

// Images are the supported guest images (Apple Silicon, arm64).
var Images = map[string]ImageSpec{
	"debian-13": {
		Name:    "debian-13",
		URL:     "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-arm64.tar.xz",
		SumsURL: "https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS",
		File:    "debian-13-genericcloud-arm64.tar.xz",
	},
}

// ImagePath returns where the extracted raw image is cached.
func ImagePath(name string) (string, error) {
	dir, err := config.ImagesDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".raw"), nil
}

// EnsureImage downloads, verifies and extracts the image if needed.
//
// NOTE: this is a direct download of a public OS image by the host. It is
// not profile traffic and carries no profile identity. Users who prefer can
// download the file themselves and use `hat image import`.
func EnsureImage(ctx context.Context, name string, log io.Writer) (string, error) {
	spec, ok := Images[name]
	if !ok {
		return "", fmt.Errorf("unknown image %q", name)
	}
	raw, err := ImagePath(name)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(raw); err == nil {
		return raw, nil
	}
	if err := os.MkdirAll(filepath.Dir(raw), 0o700); err != nil {
		return "", err
	}
	// Serialize downloads of the same image across processes.
	unlock, err := lockFile(raw + ".lock")
	if err != nil {
		return "", err
	}
	defer unlock()
	if _, err := os.Stat(raw); err == nil {
		return raw, nil // downloaded by another process meanwhile
	}
	client := &http.Client{Timeout: 60 * time.Minute}
	fmt.Fprintf(log, "Fetching checksums %s\n", spec.SumsURL)
	want, err := fetchSum(ctx, client, spec)
	if err != nil {
		return "", err
	}
	// A verified archive is kept until extraction succeeds, so a failed
	// extraction does not cause another download.
	archive := raw + ".tar.xz"
	if _, err := os.Stat(archive); err != nil {
		part := archive + ".part"
		fmt.Fprintf(log, "Downloading %s (about 200 MB, once)\n", spec.URL)
		if err := download(ctx, client, spec.URL, part, want, log); err != nil {
			return "", err
		}
		if err := os.Rename(part, archive); err != nil {
			return "", err
		}
	}
	if err := ImportImage(name, archive, log); err != nil {
		return "", fmt.Errorf("%w (the verified download is kept at %s)", err, archive)
	}
	os.Remove(archive)
	return raw, nil
}

func fetchSum(ctx context.Context, c *http.Client, spec ImageSpec) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, spec.SumsURL, nil)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s: %s", spec.SumsURL, resp.Status)
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && f[1] == spec.File && len(f[0]) == 128 {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("checksum for %s not found", spec.File)
}

// downloadAttempts bounds retries of an interrupted download.
var downloadAttempts = 5

// download fetches url into dst, resuming with HTTP Range requests after an
// interruption, then verifies the SHA-512 of the complete file.
func download(ctx context.Context, c *http.Client, url, dst, wantSHA512 string, log io.Writer) error {
	var err error
	for attempt := 1; attempt <= downloadAttempts; attempt++ {
		if err = downloadOnce(ctx, c, url, dst, log); err == nil {
			break
		}
		if ctx.Err() != nil {
			return err
		}
		if attempt < downloadAttempts {
			wait := time.Duration(1<<attempt) * time.Second
			fmt.Fprintf(log, "\n  download interrupted (%v); resuming in %s (attempt %d/%d)\n", err, wait, attempt+1, downloadAttempts)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
	}
	if err != nil {
		return fmt.Errorf("downloading %s: %w (partial file kept at %s; rerun to resume)", url, err, dst)
	}
	f, err := os.Open(dst)
	if err != nil {
		return err
	}
	h := sha512.New()
	_, err = io.Copy(h, f)
	f.Close()
	if err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA512 {
		os.Remove(dst)
		return fmt.Errorf("checksum mismatch for %s (got %s…, want %s…)", url, got[:16], wantSHA512[:16])
	}
	return nil
}

// downloadOnce continues dst from its current size.
func downloadOnce(ctx context.Context, c *http.Client, url, dst string, log io.Writer) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	have, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if have > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", have))
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	total := resp.ContentLength
	switch {
	case resp.StatusCode == http.StatusPartialContent && have > 0:
		if total >= 0 {
			total += have
		}
	case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable && have > 0:
		return nil // already complete; the checksum decides
	case resp.StatusCode == http.StatusOK:
		if err := f.Truncate(0); err != nil { // server ignored Range: start over
			return err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		have = 0
	default:
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	pr := &progress{w: log, total: total, n: have}
	n, err := io.Copy(io.MultiWriter(f, pr), resp.Body)
	pr.done()
	if err != nil {
		return err
	}
	if total >= 0 && have+n != total {
		return fmt.Errorf("short download: %d of %d bytes", have+n, total)
	}
	return nil
}

// ImportImage extracts disk.raw from a .tar.xz archive into the cache.
func ImportImage(name, archive string, log io.Writer) error {
	raw, err := ImagePath(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(raw), 0o700); err != nil {
		return err
	}
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	xr, err := xz.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		return fmt.Errorf("%s: %w", archive, err)
	}
	tr := tar.NewReader(xr)
	fmt.Fprintf(log, "Extracting disk image\n")
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("%s: disk.raw not found in archive", archive)
		}
		if err != nil {
			return err
		}
		if filepath.Base(hdr.Name) != "disk.raw" || !isRegular(hdr.Typeflag) {
			continue
		}
		tmp := raw + ".part"
		if err := writeSparse(tmp, tr, hdr.Size); err != nil {
			os.Remove(tmp)
			return err
		}
		return os.Rename(tmp, raw)
	}
}

// isRegular accepts regular files, including GNU sparse entries: Debian's
// archive stores disk.raw as type 'S', and archive/tar expands the holes
// transparently (writeSparse then keeps them as holes on disk).
func isRegular(t byte) bool {
	return t == tar.TypeReg || t == tar.TypeRegA || t == tar.TypeGNUSparse
}

// writeSparse copies r into a new file, seeking over all-zero blocks.
func writeSparse(dst string, r io.Reader, size int64) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	const bs = 64 << 10
	buf := make([]byte, bs)
	zero := make([]byte, bs)
	var off int64
	for {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			if bytes.Equal(buf[:n], zero[:n]) {
				if _, err := f.Seek(int64(n), io.SeekCurrent); err != nil {
					f.Close()
					return err
				}
			} else if _, err := f.Write(buf[:n]); err != nil {
				f.Close()
				return err
			}
			off += int64(n)
		}
		if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			f.Close()
			return err
		}
	}
	if off != size {
		f.Close()
		return fmt.Errorf("short image: %d of %d bytes", off, size)
	}
	if err := f.Truncate(size); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// CloneDisk creates the profile disk from the base image (copy-on-write
// where supported) and grows it to sizeGB.
func CloneDisk(src, dst string, sizeGB int) error {
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("%s already exists", dst)
	}
	if err := clonefile(src, dst); err != nil {
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		st, _ := in.Stat()
		if err := writeSparse(dst, in, st.Size()); err != nil {
			os.Remove(dst)
			return err
		}
	}
	st, err := os.Stat(dst)
	if err != nil {
		return err
	}
	want := int64(sizeGB) << 30
	if st.Size() < want {
		return os.Truncate(dst, want)
	}
	return nil
}

type progress struct {
	w     io.Writer
	total int64
	n     int64
	last  time.Time
}

func (p *progress) Write(b []byte) (int, error) {
	p.n += int64(len(b))
	if time.Since(p.last) > time.Second {
		p.last = time.Now()
		if p.total > 0 {
			fmt.Fprintf(p.w, "\r  %d / %d MB", p.n>>20, p.total>>20)
		} else {
			fmt.Fprintf(p.w, "\r  %d MB", p.n>>20)
		}
	}
	return len(b), nil
}

func (p *progress) done() { fmt.Fprintf(p.w, "\r  %d MB done\n", p.n>>20) }
