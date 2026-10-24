package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/term"

	"github.com/StuMP90/uencrypt/internal/keys"
)

// errNoTTY is returned when a passphrase is needed but there is no
// terminal to ask on (cron jobs, pipelines without a controlling tty).
var errNoTTY = errors.New("no terminal to prompt for a passphrase")

// openTTY opens the controlling terminal, independent of redirected
// stdin/stdout, so prompts work in pipelines.
func openTTY() (*os.File, error) {
	name := "/dev/tty"
	if runtime.GOOS == "windows" {
		name = "CONIN$"
	}
	f, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil || !term.IsTerminal(int(f.Fd())) {
		if f != nil {
			f.Close()
		}
		return nil, errNoTTY
	}
	return f, nil
}

// readPassword prompts on stderr and reads a line from the terminal
// without echo.
func readPassword(prompt string) (string, error) {
	tty, err := openTTY()
	if err != nil {
		return "", err
	}
	defer tty.Close()
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

// newPassphrase asks for a new passphrase twice. An empty answer is
// allowed only if allowEmpty.
func newPassphrase(what string, allowEmpty bool) (string, error) {
	for range 3 {
		p, err := readPassword(fmt.Sprintf("Enter %s: ", what))
		if err != nil {
			return "", err
		}
		if p == "" && !allowEmpty {
			fmt.Fprintln(os.Stderr, "The passphrase cannot be empty.")
			continue
		}
		q, err := readPassword("Confirm: ")
		if err != nil {
			return "", err
		}
		if p == q {
			return p, nil
		}
		fmt.Fprintln(os.Stderr, "Passphrases do not match.")
	}
	return "", errors.New("passphrase not confirmed")
}

// confirm asks a yes/no question on the terminal; without one it says no.
func confirm(question string) bool {
	tty, err := openTTY()
	if err != nil {
		return false
	}
	defer tty.Close()
	fmt.Fprintf(os.Stderr, "%s [y/N] ", question)
	var buf [64]byte
	n, _ := tty.Read(buf[:])
	ans := string(buf[:n])
	return len(ans) > 0 && (ans[0] == 'y' || ans[0] == 'Y')
}

// keyUnlocker unlocks keyring identities from $UENCRYPT_KEY_PASSPHRASE or
// by prompting. The environment value is tried once per key; after that
// (or without it) the terminal is used.
func keyUnlocker() *keys.Unlocker {
	tried := map[string]bool{}
	return &keys.Unlocker{Ask: func(name string) (string, error) {
		if p, ok := os.LookupEnv("UENCRYPT_KEY_PASSPHRASE"); ok && !tried[name] {
			tried[name] = true
			return p, nil
		}
		p, err := readPassword(fmt.Sprintf("Passphrase for key %q: ", name))
		if errors.Is(err, errNoTTY) {
			return "", fmt.Errorf("key %q is locked: set UENCRYPT_KEY_PASSPHRASE or run in a terminal", name)
		}
		return p, err
	}}
}

// filePassphrase returns the passphrase callback for decrypting -p files.
func filePassphrase() func() (string, error) {
	tried := false
	return func() (string, error) {
		if p, ok := os.LookupEnv("UENCRYPT_PASSPHRASE"); ok && !tried {
			tried = true
			return p, nil
		}
		p, err := readPassword("Passphrase: ")
		if errors.Is(err, errNoTTY) {
			if tried {
				return "", errors.New("UENCRYPT_PASSPHRASE is incorrect")
			}
			return "", errors.New("file is passphrase-encrypted: set UENCRYPT_PASSPHRASE or run in a terminal")
		}
		return p, err
	}
}
