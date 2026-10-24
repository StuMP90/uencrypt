package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"filippo.io/age"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/StuMP90/uencrypt/internal/keys"
)

// SSH private keys are used where they are, never copied into the keyring.
// ~/.ssh/id_ed25519 and id_rsa are tried automatically; others are chosen
// on the Decrypt page and remembered until the app quits.

// SSHKeys returns the SSH private keys chosen this session.
func (a *App) SSHKeys() []string {
	a.sshMu.Lock()
	defer a.sshMu.Unlock()
	return slices.Clone(a.sshKeys)
}

// AddSSHKey asks for an SSH private key file and adds it to the session's
// list. It returns "" if the dialog was cancelled.
func (a *App) AddSSHKey() (string, error) {
	dir := ""
	if home, err := os.UserHomeDir(); err == nil {
		if st, err := os.Stat(filepath.Join(home, ".ssh")); err == nil && st.IsDir() {
			dir = filepath.Join(home, ".ssh")
		}
	}
	// Not remembered: the next file dialog should not open in ~/.ssh.
	path, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title: "Choose an SSH private key", DefaultDirectory: dir, ShowHiddenFiles: true})
	if err != nil || path == "" {
		return "", err
	}
	if err := checkSSHKey(path); err != nil {
		return "", err
	}
	a.sshMu.Lock()
	defer a.sshMu.Unlock()
	if !slices.Contains(a.sshKeys, path) {
		a.sshKeys = append(a.sshKeys, path)
	}
	return path, nil
}

// RemoveSSHKey takes a key off the session's list.
func (a *App) RemoveSSHKey(path string) {
	a.sshMu.Lock()
	defer a.sshMu.Unlock()
	a.sshKeys = slices.DeleteFunc(a.sshKeys, func(p string) bool { return p == path })
}

// checkSSHKey makes sure path is an SSH private key age can use, without
// asking for its passphrase.
func checkSSHKey(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Contains(data, []byte("PRIVATE KEY-----")) {
		if strings.HasSuffix(path, ".pub") || keys.IsSSHRecipient(string(data)) {
			return errors.New("this is a public key: choose the private key (the file without .pub)")
		}
		return errors.New("this is not an SSH private key")
	}
	_, err = keys.ParseSSHIdentity(data, path, nil)
	if errors.Is(err, keys.ErrLocked) {
		return nil
	}
	return err
}

// sshIdentities returns the chosen SSH keys and the standard ones. A
// passphrase is asked for only when a file is encrypted to that key.
func (a *App) sshIdentities(ctx context.Context) ([]age.Identity, error) {
	ask := func(path string, retry bool) (string, error) {
		p := Prompt{Kind: "passphrase", Title: "Unlock SSH key", Confirm: "Unlock",
			Message: fmt.Sprintf("Enter the passphrase for your SSH key “%s”.", filepath.Base(path))}
		if retry {
			p.Error = "Incorrect passphrase, try again."
		}
		return a.ask(ctx, p)
	}
	var ids []age.Identity
	for _, path := range a.SSHKeys() {
		id, err := keys.LoadSSHIdentity(path, ask)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return append(ids, keys.DefaultSSHIdentities(ask)...), nil
}
