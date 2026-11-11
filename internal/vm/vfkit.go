package vm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// MinVfkit is the minimum supported vfkit version (--cloud-init).
var MinVfkit = [3]int{0, 6, 1}

type VfkitShare struct {
	Tag  string
	Path string
}

type VfkitOptions struct {
	CPUs       int
	MemoryMB   int
	EFIVars    string
	Disk       string
	NetSocket  string // unixgram socket bound by hat
	MAC        string
	ConsoleLog string
	PidFile    string
	Shares     []VfkitShare
	UserData   string // path of cloud-init user-data
	MetaData   string // path of cloud-init meta-data
}

// VfkitArgs builds the vfkit command line. The VM gets exactly one network
// device and it is attached to hat's network stack — never vfkit's NAT.
func VfkitArgs(o VfkitOptions) ([]string, error) {
	if o.NetSocket == "" || o.MAC == "" || o.Disk == "" || o.EFIVars == "" {
		return nil, errors.New("vfkit: disk, efi vars, network socket and MAC are required")
	}
	for _, v := range []string{o.NetSocket, o.MAC, o.Disk, o.EFIVars, o.ConsoleLog, o.PidFile, o.UserData, o.MetaData} {
		if strings.ContainsAny(v, ",\n") {
			return nil, fmt.Errorf("vfkit: path must not contain ',' or newline: %q", v)
		}
	}
	args := []string{
		"--cpus", strconv.Itoa(o.CPUs),
		"--memory", strconv.Itoa(o.MemoryMB),
		"--bootloader", "efi,variable-store=" + o.EFIVars + ",create",
		"--device", "virtio-blk,path=" + o.Disk,
		"--device", "virtio-net,unixSocketPath=" + o.NetSocket + ",mac=" + o.MAC,
		"--device", "virtio-rng",
	}
	if o.ConsoleLog != "" {
		args = append(args, "--device", "virtio-serial,logFilePath="+o.ConsoleLog)
	}
	for _, s := range o.Shares {
		if strings.ContainsAny(s.Path, ",\n") {
			return nil, fmt.Errorf("vfkit: shared path must not contain ',': %q", s.Path)
		}
		args = append(args, "--device", "virtio-fs,sharedDir="+s.Path+",mountTag="+s.Tag)
	}
	if o.UserData != "" {
		args = append(args, "--cloud-init", o.UserData+","+o.MetaData)
	}
	if o.PidFile != "" {
		args = append(args, "--pidfile", o.PidFile)
	}
	if err := assertSingleProxiedNIC(args); err != nil {
		return nil, err
	}
	return args, nil
}

// assertSingleProxiedNIC is a last-line check before launching vfkit.
func assertSingleProxiedNIC(args []string) error {
	nics := 0
	for i, a := range args {
		if a == "--device" && i+1 < len(args) && strings.HasPrefix(args[i+1], "virtio-net") {
			nics++
			v := args[i+1]
			if !strings.Contains(v, "unixSocketPath=") || strings.Contains(v, ",nat") || strings.Contains(v, "fd=") {
				return fmt.Errorf("refusing to start: network device is not attached to hat's proxy stack: %s", v)
			}
		}
		if a == "--restful-uri" || a == "--ignition" {
			return fmt.Errorf("refusing to start: %s is not allowed", a)
		}
	}
	if nics != 1 {
		return fmt.Errorf("refusing to start: expected exactly one network device, got %d", nics)
	}
	return nil
}

var versionRe = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

// VfkitVersion runs `vfkit --version` and checks the minimum version.
func VfkitVersion(ctx context.Context, bin string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "--version")
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("vfkit not usable (%s): %v; install with: brew install vfkit", bin, err)
	}
	m := versionRe.FindStringSubmatch(out.String())
	if m == nil {
		return "", fmt.Errorf("cannot parse vfkit version from %q", strings.TrimSpace(out.String()))
	}
	var v [3]int
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	for i := range v {
		if v[i] != MinVfkit[i] {
			if v[i] < MinVfkit[i] {
				return m[0], fmt.Errorf("vfkit %s is too old (need >= %d.%d.%d); run: brew upgrade vfkit", m[0], MinVfkit[0], MinVfkit[1], MinVfkit[2])
			}
			break
		}
	}
	return m[0], nil
}
