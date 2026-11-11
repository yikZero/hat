package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"hat/internal/config"
	"hat/internal/vm"
)

func loadVM(args []string, usage string) (*config.Profile, error) {
	name, err := needName(args, usage)
	if err != nil {
		return nil, err
	}
	p, err := config.Load(name)
	if err != nil {
		return nil, err
	}
	if p.Mode != config.ModeVM {
		return nil, fmt.Errorf("profile %q is in %s mode (no VM)", name, p.Mode)
	}
	return p, nil
}

func cmdStart(args []string) error {
	p, err := loadVM(args, "start <profile>")
	if err != nil {
		return err
	}
	if err := vm.EnsureRunning(context.Background(), p, os.Stderr); err != nil {
		return err
	}
	fmt.Printf("VM for %q is ready\n", p.Name)
	return nil
}

func cmdStop(args []string) error {
	p, err := loadVM(args, "stop <profile>")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	if err := vm.Stop(ctx, p.Name); err != nil {
		if errors.Is(err, vm.ErrNotRunning) {
			fmt.Println("Not running.")
			return nil
		}
		return err
	}
	fmt.Println("Stopped.")
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	p, err := loadVM(pos, "status <profile> [--json]")
	if err != nil {
		return err
	}
	st, err := vm.Status(context.Background(), p.Name)
	if errors.Is(err, vm.ErrNotRunning) {
		fmt.Println("stopped")
		return nil
	}
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	fmt.Printf("state       %s\nupstream    %s\nsessions    %d\nconnections %d via proxy, %d failed (blocked), %d refused\nudp dropped %d\ndns queries %d\n",
		st.State, st.Upstream, st.Sessions, st.UpstreamOK, st.UpstreamFailed, st.Refused, st.UDPDropped, st.DNSQueries)
	if st.Error != "" {
		fmt.Printf("error       %s\n", st.Error)
	}
	if st.LastError != "" {
		fmt.Printf("last proxy error  %s\n", st.LastError)
	}
	return nil
}

func cmdImage(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: %s image pull [name] | import <file.tar.xz> [--name N]", config.App)
	}
	switch args[0] {
	case "pull":
		name := "debian-13"
		if len(args) > 1 {
			name = args[1]
		}
		path, err := vm.EnsureImage(context.Background(), name, os.Stderr)
		if err != nil {
			return err
		}
		fmt.Println(path)
		return nil
	case "import":
		fs := flag.NewFlagSet("image import", flag.ContinueOnError)
		name := fs.String("name", "debian-13", "image name")
		pos, err := parseArgs(fs, args[1:])
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return fmt.Errorf("usage: %s image import <file.tar.xz> [--name N]", config.App)
		}
		return vm.ImportImage(*name, pos[0], os.Stderr)
	}
	return fmt.Errorf("unknown image command %q", args[0])
}

func cmdDaemon(args []string) error {
	if len(args) != 1 {
		return errors.New("internal command")
	}
	return vm.RunDaemon(args[0])
}
