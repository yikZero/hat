// Package secret stores and retrieves the upstream proxy password.
//
//   - "file":     ~/.hat/profiles/<p>/secret (0600). In lite mode the
//     sandbox denies reading it, so this is the recommended default.
//   - "keychain": macOS login Keychain via /usr/bin/security (encrypted at
//     rest; any process of the same user may be able to read it through
//     the security tool).
//   - "none":     the proxy needs no password.
package secret

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"hat/internal/config"
)

const keychainService = config.App + "-proxy"

// Get returns the stored password ("" for none).
func Get(p *config.Profile) (string, error) {
	switch p.Proxy.Password {
	case config.PasswordNone, "":
		return "", nil
	case config.PasswordFile:
		dir, err := config.Dir(p.Name)
		if err != nil {
			return "", err
		}
		f := filepath.Join(dir, "secret")
		st, err := os.Stat(f)
		if err != nil {
			return "", fmt.Errorf("proxy password file missing; run: %s proxy-password %s", config.App, p.Name)
		}
		if st.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("%s must not be readable by others (chmod 600)", f)
		}
		b, err := os.ReadFile(f)
		return strings.TrimRight(string(b), "\r\n"), err
	case config.PasswordKeychain:
		if runtime.GOOS != "darwin" {
			return "", errors.New("keychain storage is only available on macOS")
		}
		var out, errb bytes.Buffer
		cmd := exec.Command("/usr/bin/security", "find-generic-password", "-s", keychainService, "-a", p.Name, "-w")
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("reading proxy password from Keychain failed (run: %s proxy-password %s): %s",
				config.App, p.Name, strings.TrimSpace(errb.String()))
		}
		return strings.TrimRight(out.String(), "\r\n"), nil
	}
	return "", fmt.Errorf("unknown password storage %q", p.Proxy.Password)
}

// SetFile stores the password in the profile's secret file.
func SetFile(name, password string) error {
	dir, err := config.Dir(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return config.WriteFileAtomic(filepath.Join(dir, "secret"), []byte(password+"\n"), 0o600)
}

// SetKeychainInteractive asks /usr/bin/security to prompt for the password
// on the terminal, so it never appears on a command line.
func SetKeychainInteractive(name string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("keychain storage is only available on macOS")
	}
	cmd := exec.Command("/usr/bin/security", "add-generic-password", "-U",
		"-s", keychainService, "-a", name, "-l", config.App+" proxy password ("+name+")", "-w")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// Delete removes stored secrets for a profile (best effort).
func Delete(name string) {
	if dir, err := config.Dir(name); err == nil {
		os.Remove(filepath.Join(dir, "secret"))
	}
	if runtime.GOOS == "darwin" {
		exec.Command("/usr/bin/security", "delete-generic-password", "-s", keychainService, "-a", name).Run()
	}
}

// ProxyURL returns the full upstream URL including the password.
func ProxyURL(p *config.Profile) (string, error) {
	pw, err := Get(p)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(p.Proxy.URL)
	if err != nil {
		return "", err
	}
	if pw != "" {
		user := ""
		if u.User != nil {
			user = u.User.Username()
		}
		u.User = url.UserPassword(user, pw)
	}
	return u.String(), nil
}
