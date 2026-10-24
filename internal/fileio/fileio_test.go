package fileio

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOutputCommitAbort(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "out")

	o, err := Create(name, false, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	o.Write([]byte("partial"))
	o.Abort()
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Fatalf("aborted output exists: %v", err)
	}

	o, err = Create(name, false, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	o.Write([]byte("done"))
	if err := o.Commit(); err != nil {
		t.Fatal(err)
	}
	o.Abort() // no-op after commit
	if b, _ := os.ReadFile(name); string(b) != "done" {
		t.Fatalf("got %q", b)
	}
	if _, err := Create(name, false, 0o600); !errors.Is(err, ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestNames(t *testing.T) {
	for in, want := range map[string]string{
		"a.tar.gz.age": "a.tar.gz",
		"b.enc":        "b",
		"B.ENC":        "B",
		"c.txt":        "c.dec.txt",
		"d":            "d.dec",
		".age":         ".dec.age",
	} {
		if got := DecryptedName(in); got != want {
			t.Errorf("DecryptedName(%q) = %q, want %q", in, got, want)
		}
	}
}
