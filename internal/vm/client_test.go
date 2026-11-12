package vm

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Re-exec the test binary to exercise os.Executable through a real symlink.
// The child reports which entry point argv[0] would select, without starting
// another shim or requiring a VM.
func TestMain(m *testing.M) {
	if result := os.Getenv("HAT_TEST_SPAWN_RESULT"); result != "" {
		if len(os.Args) == 3 && os.Args[1] == "__daemon" {
			entry := "daemon"
			if filepath.Base(os.Args[0]) == "test-shim" {
				entry = "shim"
			}
			data, _ := json.Marshal(struct {
				Entry string
				Args  []string
			}{entry, os.Args})
			if err := os.WriteFile(result, data, 0o600); err != nil {
				os.Exit(1)
			}
			os.Exit(0)
		}
		if err := spawnDaemon("test-profile", Paths{DaemonLog: result + ".log"}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestSpawnDaemonFromShim(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	link := filepath.Join(dir, "test-shim")
	if err := os.Symlink(self, link); err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(dir, "child.json")
	cmd := exec.Command(link)
	cmd.Env = append(os.Environ(), "HAT_TEST_SPAWN_RESULT="+result)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("launch through shim: %v: %s", err, out)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(result)
		var child struct {
			Entry string
			Args  []string
		}
		if err == nil && json.Unmarshal(data, &child) == nil {
			if child.Entry != "daemon" {
				t.Fatalf("daemon re-entered shim dispatch: %v", child.Args)
			}
			if len(child.Args) != 3 || child.Args[1] != "__daemon" || child.Args[2] != "test-profile" {
				t.Fatalf("daemon arguments: %v", child.Args)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	log, _ := os.ReadFile(result + ".log")
	t.Fatalf("daemon child did not report its entry point: %s", log)
}
