// Package clierr defines hat's machine-readable errors and exit codes.
//
// Exit codes (management commands):
//
//	0  success
//	1  runtime error (INTERNAL)
//	2  usage error / input required (USAGE, INPUT_REQUIRED)
//	3  not found (NOT_FOUND)
//	4  proxy unreachable or rejected credentials (PROXY_UNREACHABLE, PROXY_AUTH)
//	5  preflight / leak check failed (PREFLIGHT_FAILED, EGRESS_MISMATCH)
//	6  VM failed (VM_FAILED)
//	7  already exists (EXISTS)
//
// `hat run`, `hat shell` and shims return the command's own exit code; when
// hat itself fails before or around the command they return 125 (126/127 for
// "cannot execute" / "command not found"), like `docker run`.
package clierr

import (
	"errors"
	"fmt"
)

type Code string

const (
	Internal         Code = "INTERNAL"
	Usage            Code = "USAGE"
	InputRequired    Code = "INPUT_REQUIRED"
	NotFound         Code = "NOT_FOUND"
	ProxyUnreachable Code = "PROXY_UNREACHABLE"
	ProxyAuth        Code = "PROXY_AUTH"
	PreflightFailed  Code = "PREFLIGHT_FAILED"
	EgressMismatch   Code = "EGRESS_MISMATCH"
	VMFailed         Code = "VM_FAILED"
	Exists           Code = "EXISTS"
	NotShared        Code = "CWD_NOT_SHARED"
	CommandNotFound  Code = "COMMAND_NOT_FOUND"
)

var exitCodes = map[Code]int{
	Internal: 1, Usage: 2, InputRequired: 2, NotFound: 3, ProxyUnreachable: 4, ProxyAuth: 4,
	PreflightFailed: 5, EgressMismatch: 5, VMFailed: 6, Exists: 7, NotShared: 2, CommandNotFound: 127,
}

var retryable = map[Code]bool{ProxyUnreachable: true, VMFailed: true}

// Error is a classified error with an optional remediation hint.
type Error struct {
	Code Code
	Msg  string
	Hint string
	Err  error
}

func (e *Error) Error() string {
	if e.Err != nil && e.Msg == "" {
		return e.Err.Error()
	}
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error()
	}
	return e.Msg
}

func (e *Error) Unwrap() error { return e.Err }

// New creates an error.
func New(code Code, hint string, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...), Hint: hint}
}

// Wrap classifies err (keeping an existing classification).
func Wrap(code Code, hint string, err error) error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return err
	}
	return &Error{Code: code, Err: err, Hint: hint}
}

// Classify returns the code, hint and retryability of any error.
func Classify(err error) (Code, string, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Code, e.Hint, retryable[e.Code]
	}
	return Internal, "", false
}

// ExitCode returns the management-command exit code for err.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	c, _, _ := Classify(err)
	if n, ok := exitCodes[c]; ok {
		return n
	}
	return 1
}

// Payload is the JSON shape of an error.
type Payload struct {
	Code      Code   `json:"code"`
	Message   string `json:"message"`
	Hint      string `json:"hint,omitempty"`
	Retryable bool   `json:"retryable"`
	ExitCode  int    `json:"exit_code"`
}

// ToPayload converts err for JSON output.
func ToPayload(err error, exit int) Payload {
	c, hint, r := Classify(err)
	return Payload{Code: c, Message: err.Error(), Hint: hint, Retryable: r, ExitCode: exit}
}
