package vm

import (
	"path/filepath"

	"hat/internal/config"
)

// Paths are the files belonging to one VM profile.
type Paths struct {
	Dir        string // ~/.hat/profiles/<p>
	Run        string // ~/.hat/run/<hash> (short, for sockets)
	Disk       string
	EFIVars    string
	ConsoleLog string
	DaemonLog  string
	SeedDir    string
	UserData   string
	MetaData   string
	SSHDir     string
	KnownHost  string
	NetSock    string
	CtlSock    string
	PidFile    string
	LockFile   string
}

func PathsFor(name string) (Paths, error) {
	dir, err := config.Dir(name)
	if err != nil {
		return Paths{}, err
	}
	run, err := config.RunDir(name)
	if err != nil {
		return Paths{}, err
	}
	return Paths{
		Dir: dir, Run: run,
		Disk:       filepath.Join(dir, "disk.raw"),
		EFIVars:    filepath.Join(dir, "efi-vars"),
		ConsoleLog: filepath.Join(dir, "console.log"),
		DaemonLog:  filepath.Join(dir, "daemon.log"),
		SeedDir:    filepath.Join(dir, "seed"),
		UserData:   filepath.Join(dir, "seed", "user-data"),
		MetaData:   filepath.Join(dir, "seed", "meta-data"),
		SSHDir:     filepath.Join(dir, "ssh"),
		KnownHost:  filepath.Join(dir, "ssh", "known_host"),
		NetSock:    filepath.Join(run, "net.sock"),
		CtlSock:    filepath.Join(run, "ctl.sock"),
		PidFile:    filepath.Join(run, "vfkit.pid"),
		LockFile:   filepath.Join(run, "daemon.lock"),
	}, nil
}
