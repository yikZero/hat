//go:build linux

// fakevfkit imitates vfkit for end-to-end tests on Linux: it connects to
// hat's unixgram network socket like vfkit does and runs a guest made of a
// gVisor stack (static IP 192.168.127.2) with a tiny SSH server on port 22
// that executes commands on the host with sh.
//
// The guest's virtio-fs mounts are emulated by path translation: the mount
// commands of hat's reconcile script are recorded, and a command that
// starts with "cd -- <guest dir>" runs in the matching host directory with
// GUEST_PWD set to the guest directory.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func main() {
	args := os.Args[1:]
	if len(args) == 1 && args[0] == "--version" {
		fmt.Println("vfkit version: v0.6.4 (fake)")
		return
	}
	var netSock, mac, pidFile, disk string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--pidfile":
			pidFile = args[i+1]
		case "--device":
			v := args[i+1]
			if strings.HasPrefix(v, "virtio-blk,path=") {
				disk = strings.TrimPrefix(v, "virtio-blk,path=")
			}
			if strings.HasPrefix(v, "virtio-fs,") {
				var dir, tag string
				for _, kv := range strings.Split(v, ",")[1:] {
					k, val, _ := strings.Cut(kv, "=")
					switch k {
					case "sharedDir":
						dir = val
					case "mountTag":
						tag = val
					}
				}
				tags[tag] = dir
			}
			if strings.HasPrefix(v, "virtio-net,") {
				for _, kv := range strings.Split(v, ",")[1:] {
					k, val, _ := strings.Cut(kv, "=")
					switch k {
					case "unixSocketPath":
						netSock = val
					case "mac":
						mac = val
					}
				}
			}
		}
	}
	if pidFile != "" {
		os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o644)
	}
	machineID := os.Getenv("FAKE_MACHINE_ID")

	// Connect like vfkit: bind our own unixgram socket, connect, send VFKT.
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	check(err)
	local := filepath.Join(filepath.Dir(netSock), fmt.Sprintf("vfkit-%d.sock", os.Getpid()))
	os.Remove(local)
	check(syscall.Bind(fd, &syscall.SockaddrUnix{Name: local}))
	defer os.Remove(local)
	check(syscall.Connect(fd, &syscall.SockaddrUnix{Name: netSock}))
	_, err = syscall.Write(fd, []byte("VFKT"))
	check(err)

	g := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	hw, _ := tcpip.ParseMACAddress(mac)
	link, err := fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: 1500, EthernetHeader: true, Address: hw})
	check(err)
	if e := g.CreateNIC(1, link); e != nil {
		panic(e)
	}
	g.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{192, 168, 127, 2}), PrefixLen: 24}},
		stack.AddressProperties{})
	g.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, Gateway: tcpip.AddrFrom4([4]byte{192, 168, 127, 1}), NIC: 1}})

	ln, err := gonet.ListenTCP(g, tcpip.FullAddress{NIC: 1, Port: 22}, ipv4.ProtocolNumber)
	check(err)
	// Persist the host key next to the disk, like a real guest does.
	keyFile := disk + ".hostkey"
	seed, err := os.ReadFile(keyFile)
	if err != nil || len(seed) != ed25519.SeedSize {
		seed = make([]byte, ed25519.SeedSize)
		rand.Read(seed)
		os.WriteFile(keyFile, seed, 0o600)
	}
	hs, _ := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(hs)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sigs; os.Exit(0) }()

	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go serve(c, cfg, machineID)
	}
}

func serve(c net.Conn, cfg *ssh.ServerConfig, machineID string) {
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range creqs {
				if req.Type != "exec" {
					req.Reply(false, nil)
					continue
				}
				cmdline := string(req.Payload[4:])
				req.Reply(true, nil)
				code := 0
				switch {
				case strings.Contains(cmdline, "/proc/sys/kernel/random/boot_id"): // ready probe
					fmt.Fprintln(ch, machineID)
				case strings.Contains(cmdline, "systemctl poweroff"):
					go func() { syscall.Kill(os.Getpid(), syscall.SIGTERM) }()
				case strings.HasPrefix(cmdline, "set -e"):
					// reconcile script: record the mounts, pretend success
					recordMounts(cmdline)
				default:
					cmd := exec.Command("sh", "-c", translateCd(cmdline))
					cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
					if err := cmd.Run(); err != nil {
						code = cmd.ProcessState.ExitCode()
					}
				}
				b := make([]byte, 4)
				binary.BigEndian.PutUint32(b, uint32(code))
				ch.SendRequest("exit-status", false, b)
				return
			}
		}()
	}
}

var (
	tags   = map[string]string{} // virtio-fs tag -> host dir (set before serving)
	mu     sync.Mutex
	mounts = map[string]string{} // guest dir -> host dir
)

var mountRe = regexp.MustCompile(`(?m)mount -t virtiofs -o \S+ (\S+) (.+)$`)

func recordMounts(script string) {
	mu.Lock()
	defer mu.Unlock()
	for _, m := range mountRe.FindAllStringSubmatch(script, -1) {
		if guest, rest := unquote(m[2]); rest == "" {
			mounts[guest] = tags[m[1]]
		}
	}
}

// translateCd rewrites a leading "cd -- <guest dir>" to the host directory
// it is mounted from.
func translateCd(cmdline string) string {
	rest, ok := strings.CutPrefix(cmdline, "cd -- ")
	if !ok {
		return cmdline
	}
	guest, rest := unquote(rest)
	mu.Lock()
	defer mu.Unlock()
	best := ""
	for g := range mounts {
		if (guest == g || strings.HasPrefix(guest, g+"/")) && len(g) > len(best) {
			best = g
		}
	}
	if best == "" {
		return cmdline // not mounted: the cd fails as in a real guest
	}
	host := mounts[best] + strings.TrimPrefix(guest, best)
	return "GUEST_PWD=" + quote(guest) + "; export GUEST_PWD; cd -- " + quote(host) + rest
}

// unquote reads one word quoted like session.Quote and returns the rest.
func unquote(s string) (word, rest string) {
	if !strings.HasPrefix(s, "'") {
		word, rest, _ = strings.Cut(s, " ")
		if rest != "" {
			rest = " " + rest
		}
		return word, rest
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		if s[i] != '\'' {
			b.WriteByte(s[i])
			continue
		}
		if strings.HasPrefix(s[i:], `'\''`) {
			b.WriteByte('\'')
			i += 3
			continue
		}
		return b.String(), s[i+1:]
	}
	return b.String(), ""
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fakevfkit:", err)
		os.Exit(1)
	}
}
