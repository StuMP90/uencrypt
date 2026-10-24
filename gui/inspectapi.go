package main

import (
	"crypto/rsa"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/StuMP90/uencrypt/internal/envelope"
	"github.com/StuMP90/uencrypt/internal/inspect"
)

// InspectDetail describes a file in full (how it is encrypted, who it is
// for, its sizes) without decrypting it.
func (a *App) InspectDetail(path string) (*inspect.Report, error) {
	kr, err := a.keyring()
	if err != nil {
		return nil, err
	}
	return inspect.File(a.ctx, path, inspect.Options{Keyring: kr, SSHKeys: a.SSHKeys()})
}

// LookInside is InspectDetail that also decrypts the file in memory to
// report what it holds and whether it is signed. Nothing is written.
func (a *App) LookInside(path string) (*inspect.Report, error) {
	ctx, done, err := a.begin()
	if err != nil {
		return nil, err
	}
	defer done()
	kr, err := a.keyring()
	if err != nil {
		return nil, err
	}
	ids, err := kr.DecryptionIdentities(a.unlocker(ctx))
	if err != nil {
		return nil, err
	}
	sshIDs, err := a.sshIdentities(ctx)
	if err != nil {
		return nil, err
	}
	// Legacy keys are read once: to name the key, then to decrypt.
	var legacyOnce sync.Once
	var legacyKeys []*rsa.PrivateKey
	var legacyErr error
	loadLegacy := func() ([]*rsa.PrivateKey, error) {
		legacyOnce.Do(func() { legacyKeys, legacyErr = kr.LegacyKeys() })
		return legacyKeys, legacyErr
	}
	tries := 0
	opts := inspect.Options{Keyring: kr, SSHKeys: a.SSHKeys(), Contents: true,
		Decrypt: envelope.DecryptOptions{
			Identities: append(ids, sshIDs...),
			LegacyKeys: loadLegacy,
			Passphrase: func() (string, error) {
				p := Prompt{Kind: "passphrase", Title: "Passphrase", Confirm: "Look inside",
					Message: fmt.Sprintf("“%s” is protected with a passphrase.", filepath.Base(path))}
				if tries > 0 {
					p.Error = "Incorrect passphrase, try again."
				}
				tries++
				return a.ask(ctx, p)
			},
		}}
	rep, err := inspect.File(ctx, path, opts)
	if err == nil && ctx.Err() != nil {
		return nil, errCancelled
	}
	return rep, err
}
