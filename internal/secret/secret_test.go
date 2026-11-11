package secret

import (
	"testing"

	"hat/internal/config"
)

func TestFileSecret(t *testing.T) {
	t.Setenv(config.EnvHome, t.TempDir())
	p := config.New("p1")
	p.Proxy.URL = "socks5://alice@203.0.113.9:1080"
	p.Proxy.Password = config.PasswordFile
	if _, err := ProxyURL(p); err == nil {
		t.Fatal("expected missing-secret error")
	}
	if err := SetFile("p1", "p@ss:w/rd"); err != nil {
		t.Fatal(err)
	}
	u, err := ProxyURL(p)
	if err != nil {
		t.Fatal(err)
	}
	if u != "socks5://alice:p%40ss%3Aw%2Frd@203.0.113.9:1080" {
		t.Fatalf("got %s", u)
	}
	p.Proxy.Password = config.PasswordNone
	if u, _ := ProxyURL(p); u != "socks5://alice@203.0.113.9:1080" {
		t.Fatalf("got %s", u)
	}
}
