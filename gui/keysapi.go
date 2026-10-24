package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/StuMP90/uencrypt/internal/fileio"
	"github.com/StuMP90/uencrypt/internal/keys"
	"github.com/StuMP90/uencrypt/internal/legacy"
)

// KeyInfo describes one keyring entry for the Keys page.
type KeyInfo struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"` // "identity", "contact" or "legacy"
	Default     bool   `json:"default"`
	PostQuantum bool   `json:"postQuantum"`
	Locked      bool   `json:"locked"`
	CanSign     bool   `json:"canSign"`
	Fingerprint string `json:"fingerprint"`
	Recipient   string `json:"recipient"`
	Created     string `json:"created"`
	Error       string `json:"error"`
}

type KeyringState struct {
	Dir        string    `json:"dir"`
	Default    string    `json:"default"`
	Identities []KeyInfo `json:"identities"`
	Contacts   []KeyInfo `json:"contacts"`
	Legacy     []KeyInfo `json:"legacy"`
}

func contactInfo(name, kind string, c *keys.Contact) KeyInfo {
	k := KeyInfo{Name: name, Kind: kind, PostQuantum: c.IsPostQuantum(), CanSign: c.Signer != nil,
		Fingerprint: contactFingerprint(c), Recipient: c.RecipientString}
	if !c.Created.IsZero() {
		k.Created = c.Created.Local().Format(time.DateOnly)
	}
	return k
}

// contactFingerprint is the signing fingerprint, or a shortened recipient
// for plain age keys (as the CLI shows them).
func contactFingerprint(c *keys.Contact) string {
	if c.Signer != nil {
		return c.Signer.Fingerprint()
	}
	s := c.RecipientString
	if len(s) > 24 {
		s = s[:16] + "..." + s[len(s)-6:]
	}
	return s
}

// Keyring lists everything in the keyring.
func (a *App) Keyring() (*KeyringState, error) {
	kr, err := a.keyring()
	if err != nil {
		return nil, err
	}
	st := &KeyringState{Dir: kr.Dir, Identities: []KeyInfo{}, Contacts: []KeyInfo{}, Legacy: []KeyInfo{}}
	st.Default, _ = kr.DefaultIdentity()
	ids, err := kr.Identities()
	if err != nil {
		return nil, err
	}
	for _, name := range ids {
		c, err := kr.IdentityPublic(name)
		if err != nil {
			st.Identities = append(st.Identities, KeyInfo{Name: name, Kind: "identity", Error: err.Error()})
			continue
		}
		k := contactInfo(name, "identity", c)
		k.Default = name == st.Default
		k.Locked, _ = kr.IdentityLocked(name)
		st.Identities = append(st.Identities, k)
	}
	contacts, err := kr.Contacts()
	if err != nil {
		return nil, err
	}
	for _, name := range contacts {
		c, err := kr.Contact(name)
		if err != nil {
			st.Contacts = append(st.Contacts, KeyInfo{Name: name, Kind: "contact", Error: err.Error()})
			continue
		}
		st.Contacts = append(st.Contacts, contactInfo(name, "contact", c))
	}
	leg, err := kr.LegacyNames()
	if err != nil {
		return nil, err
	}
	for _, name := range leg {
		st.Legacy = append(st.Legacy, KeyInfo{Name: name, Kind: "legacy"})
	}
	return st, nil
}

// NewIdentity creates a key pair; passphrase may be empty (an unlocked key,
// as needed for unattended use). The first identity becomes the default.
func (a *App) NewIdentity(name, passphrase string, classic, makeDefault bool) (*KeyInfo, error) {
	kr, err := a.keyring()
	if err != nil {
		return nil, err
	}
	if err := keys.ValidateName(name); err != nil {
		return nil, err
	}
	if _, err := kr.IdentityPublic(name); err == nil {
		return nil, fmt.Errorf("an identity called %q already exists", name)
	}
	id, err := keys.NewIdentity(name, classic)
	if err != nil {
		return nil, err
	}
	if err := kr.SaveIdentity(id, passphrase, false); err != nil {
		return nil, err
	}
	ids, _ := kr.Identities()
	if makeDefault || len(ids) == 1 {
		if err := kr.SetDefault(name); err != nil {
			return nil, err
		}
	}
	k := contactInfo(name, "identity", id.Contact())
	k.Locked = passphrase != ""
	return &k, nil
}

type ImportResult struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Message string `json:"message"`
	// Warning is set for things the user should act on, such as checking
	// a contact's fingerprint.
	Warning string `json:"warning"`
}

// ImportKey imports a key file: a contact card or age public key, an age
// identity, or an old RSA private key. name may be empty.
func (a *App) ImportKey(path, name string) (*ImportResult, error) {
	data, err := fileio.ReadSmallFile(path)
	if err != nil {
		return nil, err
	}
	return a.importKey(data, name, path)
}

// ImportKeyText imports pasted text, such as an age1... public key.
func (a *App) ImportKeyText(text, name string) (*ImportResult, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errors.New("nothing to import")
	}
	return a.importKey([]byte(text+"\n"), name, "")
}

func (a *App) importKey(data []byte, name, path string) (*ImportResult, error) {
	kr, err := a.keyring()
	if err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	fileName := func() (string, error) {
		if name != "" {
			return name, nil
		}
		if path == "" {
			return "", errors.New("enter a name for this key")
		}
		base := filepath.Base(path)
		for ext := filepath.Ext(base); ext != "" && ext != base; ext = filepath.Ext(base) {
			base = strings.TrimSuffix(base, ext)
		}
		return base, nil
	}
	// store runs save, offering to replace an existing entry.
	store := func(what string, save func(force bool) error) error {
		err := save(false)
		if errors.Is(err, keys.ErrExists) &&
			a.confirm(a.ctx, "Replace key?", fmt.Sprintf("Your keyring already has %s called “%s”. Replace it?", what, name), "Replace") {
			err = save(true)
		}
		return err
	}

	if keys.IsSSHPrivateKey(data) {
		return nil, errors.New("this is an SSH private key, which stays where it is: import its .pub file " +
			"as a contact instead, and choose the private key on the Decrypt page if it isn't ~/.ssh/id_ed25519 or id_rsa")
	}
	switch keys.DetectKind(data) {
	case keys.KindLegacy:
		if _, err := legacy.ParsePrivateKey(data); err != nil {
			return nil, err
		}
		if name, err = fileName(); err != nil {
			return nil, err
		}
		if err := store("a legacy key", func(f bool) error { return kr.ImportLegacy(name, data, f) }); err != nil {
			return nil, err
		}
		return &ImportResult{Kind: "legacy", Name: name,
			Message: fmt.Sprintf("Imported legacy RSA key “%s”. It is used only to decrypt old .enc files.", name)}, nil

	case keys.KindIdentity:
		pass, plain := "", data
		if keys.IsEncrypted(data) {
			u := a.unlocker(a.ctx)
			for i := 0; ; i++ {
				if pass, err = u.Ask("imported key"); err != nil {
					return nil, err
				}
				if plain, err = keys.Unlock(data, pass); err == nil {
					break
				}
				if !errors.Is(err, keys.ErrBadPassphrase) || i == 2 {
					return nil, err
				}
			}
		}
		if name == "" {
			if id, err := keys.ParseIdentity(plain); err == nil && id.Name != "" {
				name = id.Name
			} else if name, err = fileName(); err != nil {
				return nil, err
			}
		}
		var id *keys.Identity
		if err := store("an identity", func(f bool) error {
			id, err = kr.ImportIdentity(name, data, pass, f)
			return err
		}); err != nil {
			return nil, err
		}
		if ids, _ := kr.Identities(); len(ids) == 1 {
			kr.SetDefault(name)
		}
		r := &ImportResult{Kind: "identity", Name: name, Message: fmt.Sprintf("Imported your key “%s”.", name)}
		if id.Signer == nil {
			r.Message += " It has no signing key, so it can decrypt but not sign."
		}
		if pass == "" {
			r.Warning = "This key is stored without a passphrase. Add one from the key's menu unless it is used for unattended jobs."
		}
		return r, nil

	default:
		c, err := keys.ParseContact(data)
		if err != nil {
			return nil, err
		}
		if name == "" {
			if c.Name != "" {
				name = c.Name
			} else if name, err = fileName(); err != nil {
				return nil, err
			}
		}
		c.Name = name
		if err := store("a contact", func(f bool) error { return kr.AddContact(c, f) }); err != nil {
			return nil, err
		}
		r := &ImportResult{Kind: "contact", Name: name, Message: fmt.Sprintf("Imported contact “%s”.", name)}
		if strings.HasPrefix(keys.StanzaType(c.Recipient), "ssh-") {
			r.Warning = "This is an SSH key: you can encrypt to it, but it is classic (not post-quantum) and cannot sign."
		} else if c.Signer != nil {
			r.Warning = "Check the signing fingerprint " + c.Signer.Fingerprint() +
				" with its owner (by phone or in person) before trusting signatures from it."
		} else {
			r.Warning = "This is a plain age key: you can encrypt to it, but it cannot sign."
		}
		return r, nil
	}
}

func (a *App) publicKey(name string) (*keys.Contact, error) {
	kr, err := a.keyring()
	if err != nil {
		return nil, err
	}
	return kr.Recipient(name)
}

// ContactText returns the shareable contact card for a key.
func (a *App) ContactText(name string) (string, error) {
	c, err := a.publicKey(name)
	if err != nil {
		return "", err
	}
	return string(c.Marshal()), nil
}

// ExportContact saves a key's contact card; it returns the path, or "" if
// the user cancelled.
func (a *App) ExportContact(name string) (string, error) {
	c, err := a.publicKey(name)
	if err != nil {
		return "", err
	}
	path, err := a.pickSave("Save contact card", name+".pub")
	if err != nil || path == "" {
		return "", err
	}
	return path, os.WriteFile(path, c.Marshal(), 0o644)
}

// ExportSecret saves a backup of an own identity, as stored (locked if it
// has a passphrase).
func (a *App) ExportSecret(name string) (string, error) {
	kr, err := a.keyring()
	if err != nil {
		return "", err
	}
	data, err := kr.IdentityFile(name)
	if err != nil {
		return "", err
	}
	if !keys.IsEncrypted(data) && !a.confirm(a.ctx, "Export unprotected key?",
		"This key has no passphrase, so anyone with the exported file can decrypt your files and sign as you. Keep the backup somewhere safe.",
		"Export anyway") {
		return "", nil
	}
	path, err := a.pickSave("Back up secret key", name+".key")
	if err != nil || path == "" {
		return "", err
	}
	return path, os.WriteFile(path, data, 0o600)
}

func (a *App) SetDefault(name string) error {
	kr, err := a.keyring()
	if err != nil {
		return err
	}
	return kr.SetDefault(name)
}

// ChangePassphrase re-saves an identity with a new passphrase ("" removes
// it). The current passphrase is asked for if the key is locked.
func (a *App) ChangePassphrase(name, passphrase string) error {
	kr, err := a.keyring()
	if err != nil {
		return err
	}
	id, err := kr.LoadIdentity(name, a.unlocker(a.ctx))
	if err != nil {
		return err
	}
	return kr.SaveIdentity(id, passphrase, true)
}

// Remove deletes a keyring entry after confirmation; it reports whether
// it was removed.
func (a *App) Remove(kind, name string) (bool, error) {
	kr, err := a.keyring()
	if err != nil {
		return false, err
	}
	var k keys.Kind
	msg := fmt.Sprintf("Remove the contact “%s”? You can import it again later.", name)
	switch kind {
	case "identity":
		k = keys.KindIdentity
		msg = fmt.Sprintf("Delete your key “%s”? Files encrypted to it can no longer be decrypted unless you have a backup.", name)
	case "contact":
		k = keys.KindContact
	case "legacy":
		k = keys.KindLegacy
		msg = fmt.Sprintf("Remove the legacy key “%s”? Old .enc files for it can no longer be decrypted unless you have the .pem file.", name)
	default:
		return false, fmt.Errorf("unknown key kind %q", kind)
	}
	if !a.confirm(a.ctx, "Remove key?", msg, "Remove") {
		return false, nil
	}
	return true, kr.Remove(k, name)
}

// OpenKeyringFolder shows the keyring directory in the file manager.
func (a *App) OpenKeyringFolder() error {
	kr, err := a.keyring()
	if err != nil {
		return err
	}
	return a.RevealInFolder(kr.Dir)
}
