// Package shim manages command shims: symlinks in ~/.hat/bin that point
// at the hat binary, which dispatches on argv[0].
package shim

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"hat/internal/config"
)

type Entry struct {
	// Command is the program to run inside the profile.
	Command string `toml:"command"`
	// Profile is the profile this shim uses.
	Profile string `toml:"profile"`
	// Pinned shims ignore HAT_PROFILE (names like teil@jp are pinned).
	Pinned bool `toml:"pinned,omitempty"`
	// Real is the host path of the program (lite mode), using the stable
	// path (e.g. /opt/homebrew/bin/teil, not the Cellar realpath).
	Real string `toml:"real,omitempty"`
}

type File struct {
	Shims map[string]Entry `toml:"shims"`
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9._+-]+(@[a-z0-9_-]+)?$`)

func path() (string, error) {
	h, err := config.Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "shims.toml"), nil
}

func Load() (*File, error) {
	p, err := path()
	if err != nil {
		return nil, err
	}
	f := &File{Shims: map[string]Entry{}}
	if _, err := toml.DecodeFile(p, f); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if f.Shims == nil {
		f.Shims = map[string]Entry{}
	}
	return f, nil
}

func (f *File) Save() error {
	p, err := path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString("# hat shims — managed by `hat shim add/rm`\n")
	if err := toml.NewEncoder(&buf).Encode(f); err != nil {
		return err
	}
	return config.WriteFileAtomic(p, buf.Bytes(), 0o644)
}

// Names returns shim names sorted.
func (f *File) Names() []string {
	var n []string
	for k := range f.Shims {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// HatBinary returns the path shims should point at: the stable `hat` found
// on PATH if it is this same binary, otherwise this executable.
func HatBinary() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	selfReal, _ := filepath.EvalSymlinks(self)
	if lp, err := exec.LookPath(config.App); err == nil {
		if abs, err := filepath.Abs(lp); err == nil {
			if r, _ := filepath.EvalSymlinks(abs); r == selfReal {
				return abs, nil
			}
		}
	}
	return self, nil
}

// LookPathExcluding finds cmd on PATH, skipping dir (the shim directory).
func LookPathExcluding(cmd, dir string) (string, error) {
	if strings.Contains(cmd, "/") {
		return filepath.Abs(cmd)
	}
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		if d == "" || sameDir(d, dir) {
			continue
		}
		p := filepath.Join(d, cmd)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: not found on PATH (outside %s)", cmd, dir)
}

func sameDir(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	if err1 != nil || err2 != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return ra == rb
}

// Add creates or replaces a shim.
func Add(name string, e Entry) error {
	if !nameRe.MatchString(name) || name == config.App || strings.HasPrefix(name, ".") {
		return fmt.Errorf("invalid shim name %q", name)
	}
	if _, after, ok := strings.Cut(name, "@"); ok {
		e.Pinned = true
		if e.Profile == "" {
			e.Profile = after
		}
	}
	if err := config.ValidName(e.Profile); err != nil {
		return err
	}
	bin, err := config.BinDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(bin, 0o755); err != nil {
		return err
	}
	target, err := HatBinary()
	if err != nil {
		return err
	}
	link := filepath.Join(bin, name)
	os.Remove(link)
	if err := os.Symlink(target, link); err != nil {
		return err
	}
	f, err := Load()
	if err != nil {
		return err
	}
	f.Shims[name] = e
	return f.Save()
}

// Remove deletes a shim.
func Remove(name string) error {
	f, err := Load()
	if err != nil {
		return err
	}
	if _, ok := f.Shims[name]; !ok {
		return fmt.Errorf("no shim named %q", name)
	}
	delete(f.Shims, name)
	bin, _ := config.BinDir()
	os.Remove(filepath.Join(bin, name))
	return f.Save()
}

// EnsureHelpers creates helper symlinks (the BROWSER url printer).
func EnsureHelpers(helperName string) error {
	bin, err := config.BinDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(bin, 0o755); err != nil {
		return err
	}
	target, err := HatBinary()
	if err != nil {
		return err
	}
	link := filepath.Join(bin, helperName)
	if cur, err := os.Readlink(link); err == nil && cur == target {
		return nil
	}
	os.Remove(link)
	return os.Symlink(target, link)
}

// Resolve decides which profile a shim invocation uses.
//
//	HAT_ACTIVE set   -> nested call: must be the same profile
//	pinned shim      -> its profile
//	HAT_PROFILE set  -> that profile
//	otherwise        -> the shim's profile
func Resolve(e Entry, env func(string) string) (profile string, nested bool, err error) {
	profile = e.Profile
	if !e.Pinned {
		if p := env(config.EnvProfile); p != "" {
			profile = p
		}
	}
	if active := env(config.EnvActive); active != "" {
		if active != profile {
			return "", true, fmt.Errorf("already running inside profile %q; refusing to switch to %q from inside it", active, profile)
		}
		return profile, true, nil
	}
	return profile, false, nil
}
