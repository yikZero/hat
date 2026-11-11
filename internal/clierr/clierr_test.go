package clierr

import (
	"errors"
	"fmt"
	"testing"
)

func TestClassify(t *testing.T) {
	e := New(ProxyUnreachable, "check the proxy", "proxy %s down", "h:1")
	wrapped := fmt.Errorf("starting: %w", e)
	if c, h, r := Classify(wrapped); c != ProxyUnreachable || h != "check the proxy" || !r {
		t.Fatal(c, h, r)
	}
	if ExitCode(wrapped) != 4 || ExitCode(errors.New("x")) != 1 || ExitCode(nil) != 0 {
		t.Fatal("exit codes")
	}
	if Wrap(NotFound, "", e) != e {
		t.Fatal("Wrap must keep existing classification")
	}
	p := ToPayload(Wrap(NotFound, "create it", errors.New("no profile")), 3)
	if p.Code != NotFound || p.Message != "no profile" || p.Hint != "create it" || p.ExitCode != 3 {
		t.Fatalf("%+v", p)
	}
}
