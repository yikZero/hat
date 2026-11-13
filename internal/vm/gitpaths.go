package vm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"hat/internal/config"
	"hat/internal/session"
)

// Git records some locations as absolute host paths: a linked worktree's
// .git file ("gitdir: /Users/<you>/repo/.git/worktrees/wt") and the
// back-pointer in that directory ("gitdir"). Shares are mounted at other
// paths in the guest (see config.GuestMount), so git cannot follow them
// there. Recreating the host paths in the guest would put the macOS account
// name back, so instead the guest sees those files with guest paths: each is
// covered by a bind mount of a copy under gitPathsDir. Nothing on the host
// changes.
const gitPathsDir = "/run/git-paths"

// gitConfigScript keeps git in the guest from deleting the metadata of
// worktrees it cannot see. Worktrees outside the shares look missing from
// the guest, and automatic gc ("git worktree prune") would remove their
// entries from the shared repository after gc.worktreePruneExpire.
const gitConfigScript = `grep -qs 'worktreePruneExpire' /etc/gitconfig || ` +
	`printf '\n[gc]\n\tworktreePruneExpire = never\n' | sudo tee -a /etc/gitconfig >/dev/null
`

// gitFixFunc is the guest shell function that makes file $1 read $2: it
// writes the copy and bind-mounts it unless the file already says so. A
// copy that is already mounted is updated in place.
const gitFixFunc = `fix() { t=` + gitPathsDir + `/$(printf %s "$1" | sha256sum | cut -c1-24); ` +
	`sudo mkdir -p ` + gitPathsDir + ` && printf '%s\n' "$2" | sudo tee "$t" >/dev/null && ` +
	`sudo chown "$(id -u):$(id -g)" "$t" && ` +
	`{ [ "$(cat "$1" 2>/dev/null)" = "$2" ] || sudo mount --bind "$t" "$1"; }; }
`

// GitPathScript returns a guest script that makes git usable in the VM when
// hostDir (the host working directory, inside a share) belongs to a linked
// git worktree whose .git file holds an absolute host path. It returns ""
// when nothing needs fixing. warning is set when git cannot work there
// (the worktree's repository is not shared); it never contains anything
// but host paths the user already knows, and is printed on the host only.
func GitPathScript(p *config.Profile, hostDir string) (script, warning string) {
	wt, gitFile, ok := findDotGitFile(p, hostDir)
	if !ok {
		return "", ""
	}
	adminHost, ok := readGitdir(gitFile)
	if !ok || !filepath.IsAbs(adminHost) {
		return "", "" // relative paths work in the guest as they are
	}
	adminGuest, _, ok := p.GuestPath(adminHost)
	if !ok {
		return "", fmt.Sprintf("this git worktree belongs to %s, which is not shared with profile %q: "+
			"git will not work here in the VM (share the repository: %s share add %s <repo>)",
			adminHost, p.Name, config.App, p.Name)
	}
	wtGuest, _, _ := p.GuestPath(wt)
	q := session.Quote
	var sb strings.Builder
	sb.WriteString("set -e\n")
	sb.WriteString(gitFixFunc)
	fmt.Fprintf(&sb, "fix %s %s\n", q(wtGuest+"/.git"), q("gitdir: "+adminGuest))
	// The back-pointer, used by "git worktree list/prune/repair".
	if back, ok := readLine(filepath.Join(adminHost, "gitdir")); ok && filepath.IsAbs(back) {
		if backGuest, _, ok := p.GuestPath(back); ok {
			fmt.Fprintf(&sb, "[ ! -f %[1]s ] || fix %[1]s %[2]s\n", q(adminGuest+"/gitdir"), q(backGuest))
		}
	}
	return sb.String(), ""
}

// findDotGitFile walks up from dir, within the shares, to the nearest .git
// entry and reports it if it is a file (a linked worktree; submodules use
// relative paths and need nothing).
func findDotGitFile(p *config.Profile, dir string) (root, gitFile string, ok bool) {
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if _, _, shared := p.GuestPath(d); !shared {
			return "", "", false
		}
		f := filepath.Join(d, ".git")
		if st, err := os.Stat(f); err == nil {
			return d, f, st.Mode().IsRegular()
		}
		if d == filepath.Dir(d) {
			return "", "", false
		}
	}
}

func readGitdir(file string) (string, bool) {
	line, ok := readLine(file)
	if !ok {
		return "", false
	}
	v, ok := strings.CutPrefix(line, "gitdir:")
	return strings.TrimSpace(v), ok
}

func readLine(file string) (string, bool) {
	b, err := os.ReadFile(file)
	if err != nil || len(b) > 4096 {
		return "", false
	}
	line, _, _ := strings.Cut(string(b), "\n")
	line = strings.TrimSpace(line)
	return line, line != ""
}
