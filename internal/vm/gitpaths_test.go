package vm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"hat/internal/config"
)

// worktreeFixture makes a repository ~/code/repo with a linked worktree
// ~/code/wt, both recorded with absolute host paths (as git does unless
// worktree.useRelativePaths is set).
func worktreeFixture(t *testing.T) (home, repo, wt string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	home = t.TempDir()
	t.Setenv("HOME", home)
	repo = filepath.Join(home, "code", "repo")
	wt = filepath.Join(home, "code", "wt")
	git := func(dir string, args ...string) {
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com",
			"-c", "worktree.useRelativePaths=false"}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	os.MkdirAll(repo, 0o755)
	git(repo, "init", "-q")
	git(repo, "commit", "-q", "--allow-empty", "-m", "init")
	git(repo, "worktree", "add", "-q", wt)
	os.MkdirAll(filepath.Join(wt, "sub"), 0o755)
	if b, _ := os.ReadFile(filepath.Join(wt, ".git")); !strings.Contains(string(b), "gitdir: /") {
		t.Skipf("this git writes relative worktree paths: %s", b)
	}
	return home, repo, wt
}

func TestGitPathScriptMapsWorktree(t *testing.T) {
	home, _, wt := worktreeFixture(t)
	p := config.New("x")
	p.Share = []config.Share{{Path: "~/code"}}
	script, warning := GitPathScript(p, filepath.Join(wt, "sub"))
	if warning != "" {
		t.Fatalf("warning: %s", warning)
	}
	for _, want := range []string{
		"fix /home/dev/code/wt/.git 'gitdir: /home/dev/code/repo/.git/worktrees/wt'\n",
		"fix /home/dev/code/repo/.git/worktrees/wt/gitdir /home/dev/code/wt/.git\n",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("missing %q in:\n%s", want, script)
		}
	}
	if strings.Contains(script, home) {
		t.Errorf("host path in guest script:\n%s", script)
	}

	// Emulate the guest: /home/dev is a view of the host home, sudo is a
	// no-op and a bind mount is a copy. git must then work in the worktree
	// through the guest paths.
	guest := t.TempDir()
	os.MkdirAll(filepath.Join(guest, "home"), 0o755)
	if err := os.Symlink(home, filepath.Join(guest, "home", "dev")); err != nil {
		t.Skip(err)
	}
	emu := strings.NewReplacer("/home/dev", guest+"/home/dev", gitPathsDir, guest+"/run", "sudo mount --bind", "cp",
		"sudo ", "").Replace(script)
	for i := 0; i < 2; i++ { // idempotent
		if out, err := exec.Command("sh", "-c", emu).CombinedOutput(); err != nil {
			t.Fatalf("guest script: %v\n%s\n%s", err, out, emu)
		}
	}
	cmd := exec.Command("git", "status", "--short", "--branch")
	cmd.Dir = filepath.Join(guest, "home", "dev", "code", "wt", "sub")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git status through guest paths: %v\n%s", err, out)
	}
}

func TestGitPathScriptNothingToDo(t *testing.T) {
	_, repo, wt := worktreeFixture(t)
	p := config.New("x")
	p.Share = []config.Share{{Path: "~/code"}}
	if s, w := GitPathScript(p, repo); s != "" || w != "" {
		t.Errorf("main checkout: %q %q", s, w)
	}
	if s, w := GitPathScript(p, filepath.Dir(repo)); s != "" || w != "" {
		t.Errorf("not a repository: %q %q", s, w)
	}
	os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: ../repo/.git/worktrees/wt\n"), 0o644)
	if s, w := GitPathScript(p, wt); s != "" || w != "" {
		t.Errorf("relative gitdir: %q %q", s, w)
	}
}

func TestGitPathScriptRepoNotShared(t *testing.T) {
	_, _, wt := worktreeFixture(t)
	p := config.New("x")
	p.Share = []config.Share{{Path: "~/code/wt"}}
	s, w := GitPathScript(p, wt)
	if s != "" || !strings.Contains(w, "not shared") {
		t.Fatalf("got %q %q", s, w)
	}
}

func TestGitConfigScriptIdempotent(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc", "gitconfig"), []byte("[user]\n\tname = x"), 0o644) // no final newline
	for i := 0; i < 2; i++ {
		if out, err := guestSh(t, root, "set -e\n"+gitConfigScript); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	b, _ := os.ReadFile(filepath.Join(root, "etc", "gitconfig"))
	if got := string(b); got != "[user]\n\tname = x\n[gc]\n\tworktreePruneExpire = never\n" {
		t.Fatalf("gitconfig:\n%s", got)
	}
	if _, err := exec.LookPath("git"); err == nil {
		out, err := exec.Command("git", "config", "--file", filepath.Join(root, "etc", "gitconfig"), "gc.worktreePruneExpire").Output()
		if err != nil || strings.TrimSpace(string(out)) != "never" {
			t.Fatalf("git reads %q %v", out, err)
		}
	}
}
