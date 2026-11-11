package vm

import (
	"context"
	"fmt"
	"io"
	"os"

	"hat/internal/config"
)

// Prepare makes sure the profile's disk, SSH key and cloud-init seed exist.
// It may download the base image (with progress on log).
func Prepare(ctx context.Context, p *config.Profile, log io.Writer) error {
	paths, err := PathsFor(p.Name)
	if err != nil {
		return err
	}
	st, err := config.LoadState(p.Name)
	if err != nil {
		return err
	}
	for _, d := range []string{paths.Dir, paths.SeedDir, paths.SSHDir, paths.Run} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	if _, err := os.Stat(paths.Disk); os.IsNotExist(err) {
		base, err := EnsureImage(ctx, p.VM.Image, log)
		if err != nil {
			return fmt.Errorf("guest image: %w", err)
		}
		fmt.Fprintf(log, "Creating %d GB disk for profile %s\n", p.VM.DiskGB, p.Name)
		if err := CloneDisk(base, paths.Disk, p.VM.DiskGB); err != nil {
			return err
		}
	}
	_, authorized, err := EnsureKey(paths.SSHDir)
	if err != nil {
		return err
	}
	in := SeedInput{
		InstanceID:    "hat-" + p.Name + "-" + st.MachineID[:8],
		Hostname:      p.VM.Hostname,
		Username:      p.VM.Username,
		UID:           GuestUID,
		MachineID:     st.MachineID,
		AuthorizedKey: authorized,
		Timezone:      p.Timezone,
		Locale:        p.Locale,
		Provision:     p.VM.Provision,
	}
	if err := config.WriteFileAtomic(paths.UserData, []byte(UserData(in)), 0o600); err != nil {
		return err
	}
	return config.WriteFileAtomic(paths.MetaData, []byte(MetaData(in)), 0o600)
}
