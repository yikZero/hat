//go:build !darwin

package vm

import "errors"

func clonefile(src, dst string) error { return errors.New("clonefile not supported") }
