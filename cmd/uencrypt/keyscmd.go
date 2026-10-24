package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/StuMP90/uencrypt/internal/keys"
	"github.com/StuMP90/uencrypt/internal/legacy"
)

const keysHelp = `Usage: uencrypt keys COMMAND [options]

Commands:
  list                       show identities, contacts and legacy keys
  new NAME                   create an identity (encryption + signing keys)
      --classic              use a classic X25519 key (for recipients with
                             age tools older than v1.3); not quantum-resistant
      --no-passphrase        store the key unlocked (for unattended use)
      --default              make it the default identity
  import FILE|KEY|-          import a contact card, an age1... or SSH public
                             key (or .pub file), an identity file or an old
                             RSA .pem key
      --name NAME            name to store it under
      -f, --force            replace an existing entry with that name
  export NAME                print your public contact card for NAME
      --secret               export the private identity file instead
      -o, --output OUT       write to OUT instead of stdout
  remove [--contact|--legacy] NAME
      -f, --force            remove an identity without asking
  default [NAME]             show or set the default identity
  passwd NAME                change, add or remove an identity's passphrase
  path                       print the keyring directory

The passphrase for new keys is read from $UENCRYPT_KEY_PASSPHRASE when
there is no terminal.
`

func (a *app) keys(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(a.stdout, keysHelp)
		if len(args) == 0 {
			return usagef("missing keys command")
		}
		return flag.ErrHelp
	}
	cmds := map[string]func([]string) error{
		"list":    a.keysList,
		"ls":      a.keysList,
		"new":     a.keysNew,
		"import":  a.keysImport,
		"export":  a.keysExport,
		"remove":  a.keysRemove,
		"rm":      a.keysRemove,
		"default": a.keysDefault,
		"passwd":  a.keysPasswd,
		"path":    a.keysPath,
	}
	cmd, ok := cmds[args[0]]
	if !ok {
		return usagef("unknown keys command %q (see uencrypt keys -h)", args[0])
	}
	return cmd(args[1:])
}

func (a *app) keysList(args []string) error {
	fs := a.newFlags("keys list", keysHelp)
	if rest, err := a.parse(fs, args); err != nil {
		return err
	} else if len(rest) > 0 {
		return usagef("keys list takes no arguments")
	}
	kr, err := a.openKeyring()
	if err != nil {
		return err
	}
	w := a.stdout
	def, _ := kr.DefaultIdentity()
	ids, err := kr.Identities()
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "Identities:")
	if len(ids) == 0 {
		fmt.Fprintln(w, "  (none: create one with 'uencrypt keys new NAME')")
	}
	for _, name := range ids {
		var flags []string
		if name == def {
			flags = append(flags, "default")
		}
		c, err := kr.IdentityPublic(name)
		if err != nil {
			fmt.Fprintf(w, "  %-20s error: %v\n", name, err)
			continue
		}
		flags = append(flags, pqFlag(c))
		if locked, _ := kr.IdentityLocked(name); locked {
			flags = append(flags, "locked")
		}
		if c.Signer == nil {
			flags = append(flags, "no signing key")
		}
		fmt.Fprintf(w, "  %-20s %s  [%s]\n", name, contactFingerprint(c), strings.Join(flags, ", "))
	}

	contacts, err := kr.Contacts()
	if err != nil {
		return err
	}
	if len(contacts) > 0 {
		fmt.Fprintln(w, "\nContacts:")
	}
	for _, name := range contacts {
		c, err := kr.Contact(name)
		if err != nil {
			fmt.Fprintf(w, "  %-20s error: %v\n", name, err)
			continue
		}
		flags := []string{pqFlag(c)}
		if c.Signer == nil {
			flags = append(flags, "cannot sign")
		}
		fmt.Fprintf(w, "  %-20s %s  [%s]\n", name, contactFingerprint(c), strings.Join(flags, ", "))
	}

	leg, err := kr.LegacyNames()
	if err != nil {
		return err
	}
	if len(leg) > 0 {
		fmt.Fprintln(w, "\nLegacy RSA keys (decrypt only):")
	}
	for _, name := range leg {
		fmt.Fprintf(w, "  %s\n", name)
	}
	return nil
}

func pqFlag(c *keys.Contact) string {
	if c.IsPostQuantum() {
		return "post-quantum"
	}
	return "classic"
}

// contactFingerprint is the signing fingerprint, or a shortened recipient
// for plain age keys.
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

func (a *app) keysNew(args []string) error {
	fs := a.newFlags("keys new", keysHelp)
	var classic, noPass, setDefault bool
	fs.BoolVar(&classic, "classic", false, "")
	fs.BoolVar(&noPass, "no-passphrase", false, "")
	fs.BoolVar(&setDefault, "default", false, "")
	rest, err := a.parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return usagef("usage: keys new NAME")
	}
	name := rest[0]
	if err := keys.ValidateName(name); err != nil {
		return usagef("%v", err)
	}
	kr, err := a.openKeyring()
	if err != nil {
		return err
	}
	if _, err := kr.IdentityPublic(name); err == nil {
		return fmt.Errorf("identity %q %w", name, keys.ErrExists)
	}
	pass := ""
	if !noPass {
		if pass, err = keyPassphrase(name); err != nil {
			return err
		}
	}
	id, err := keys.NewIdentity(name, classic)
	if err != nil {
		return err
	}
	if err := kr.SaveIdentity(id, pass, false); err != nil {
		return err
	}
	ids, _ := kr.Identities()
	if setDefault || len(ids) == 1 {
		if err := kr.SetDefault(name); err != nil {
			return err
		}
	}
	c := id.Contact()
	fmt.Fprintf(a.stderr, "Created identity %q (%s%s)\n", name, pqFlag(c), map[bool]string{true: ", unlocked"}[pass == ""])
	fmt.Fprintf(a.stderr, "Signing fingerprint: %s\n", c.Signer.Fingerprint())
	fmt.Fprintf(a.stderr, "Share your contact card with: uencrypt keys export %s > %s.pub\n", name, name)
	return nil
}

// keyPassphrase gets the passphrase for a new key: from the terminal (empty
// allowed), else $UENCRYPT_KEY_PASSPHRASE.
func keyPassphrase(name string) (string, error) {
	p, err := newPassphrase(fmt.Sprintf("passphrase for %q (empty for none)", name), true)
	if errors.Is(err, errNoTTY) {
		if p, ok := os.LookupEnv("UENCRYPT_KEY_PASSPHRASE"); ok {
			return p, nil
		}
		return "", errors.New("no terminal: set UENCRYPT_KEY_PASSPHRASE or use --no-passphrase")
	}
	return p, err
}

func (a *app) keysImport(args []string) error {
	fs := a.newFlags("keys import", keysHelp)
	var name string
	var force bool
	fs.StringVar(&name, "name", "", "")
	fs.BoolVar(&force, "f", false, "")
	fs.BoolVar(&force, "force", false, "")
	rest, err := a.parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return usagef("usage: keys import [--name NAME] FILE|age1...|ssh-...|-")
	}
	src := rest[0]
	kr, err := a.openKeyring()
	if err != nil {
		return err
	}

	var data []byte
	if keys.IsSSHRecipient(src) {
		// The name defaults to the key's comment.
		data = []byte(src + "\n")
	} else if strings.HasPrefix(src, "age1") {
		if name == "" {
			return usagef("--name is required when importing a bare age1... key")
		}
		data = []byte(src + "\n")
	} else if data, err = readSmallFile(src); err != nil {
		return err
	}
	fileName := func() (string, error) {
		if name != "" {
			return name, nil
		}
		if src == "-" {
			return "", usagef("--name is required when importing from stdin")
		}
		base := filepath.Base(src)
		for {
			ext := filepath.Ext(base)
			if ext == "" || ext == base {
				break
			}
			base = strings.TrimSuffix(base, ext)
		}
		return base, nil
	}

	if keys.IsSSHPrivateKey(data) {
		return keys.ErrSSHPrivateKey
	}
	switch keys.DetectKind(data) {
	case keys.KindLegacy:
		if _, err := legacy.ParsePrivateKey(data); err != nil {
			return err
		}
		if name, err = fileName(); err != nil {
			return err
		}
		if err := kr.ImportLegacy(name, data, force); err != nil {
			return err
		}
		fmt.Fprintf(a.stderr, "Imported legacy RSA key %q (decrypt only)\n", name)

	case keys.KindIdentity:
		pass := ""
		plain := data
		if keys.IsEncrypted(data) {
			for i := 0; ; i++ {
				if pass, err = readPassword("Passphrase for the imported identity: "); err != nil {
					return err
				}
				if plain, err = keys.Unlock(data, pass); err == nil {
					break
				}
				if !errors.Is(err, keys.ErrBadPassphrase) || i == 2 {
					return err
				}
			}
		}
		if name == "" {
			if id, err := keys.ParseIdentity(plain); err == nil && id.Name != "" {
				name = id.Name
			} else if name, err = fileName(); err != nil {
				return err
			}
		}
		id, err := kr.ImportIdentity(name, data, pass, force)
		if err != nil {
			return err
		}
		extra := ""
		if id.Signer == nil {
			extra = "; it has no signing key"
		}
		fmt.Fprintf(a.stderr, "Imported identity %q (%s%s)\n", name, pqFlag(id.Contact()), extra)
		if keys.IsEncrypted(data) {
			break
		}
		a.warnf("the identity is stored unlocked; add a passphrase with 'uencrypt keys passwd %s'", name)

	default:
		c, err := keys.ParseContact(data)
		if err != nil {
			return err
		}
		if name == "" {
			if c.Name != "" {
				name = c.Name
			} else if name, err = fileName(); err != nil {
				return err
			}
		}
		c.Name = name
		if err := kr.AddContact(c, force); err != nil {
			return err
		}
		fp := "no signing key"
		if c.Signer != nil {
			fp = "signing fingerprint " + c.Signer.Fingerprint()
		}
		if strings.HasPrefix(keys.StanzaType(c.Recipient), "ssh-") {
			fmt.Fprintf(a.stderr, "Imported contact %q (classic SSH key, encryption only)\n", name)
			break
		}
		fmt.Fprintf(a.stderr, "Imported contact %q (%s, %s)\n", name, pqFlag(c), fp)
		fmt.Fprintln(a.stderr, "Check the fingerprint with its owner before trusting signatures from it.")
	}
	return nil
}

func (a *app) keysExport(args []string) error {
	fs := a.newFlags("keys export", keysHelp)
	var secret, force bool
	var out string
	fs.BoolVar(&secret, "secret", false, "")
	fs.StringVar(&out, "o", "", "")
	fs.StringVar(&out, "output", "", "")
	fs.BoolVar(&force, "f", false, "")
	fs.BoolVar(&force, "force", false, "")
	rest, err := a.parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) > 1 {
		return usagef("usage: keys export [--secret] [-o OUT] NAME")
	}
	kr, err := a.openKeyring()
	if err != nil {
		return err
	}
	name := ""
	if len(rest) == 1 {
		name = rest[0]
	} else if name, err = kr.DefaultIdentity(); err != nil {
		return err
	}

	var data []byte
	perm := os.FileMode(0o644)
	if secret {
		if data, err = kr.IdentityFile(name); err != nil {
			return err
		}
		perm = 0o600
		if !keys.IsEncrypted(data) {
			a.warnf("exporting an unlocked private key")
		}
	} else {
		c, err := kr.Recipient(name)
		if err != nil {
			return err
		}
		data = c.Marshal()
	}
	if out == "" {
		out = "-"
	}
	o, err := createOutput(out, force, false, perm)
	if err != nil {
		return err
	}
	defer o.Abort()
	if _, err := o.Write(data); err != nil {
		return err
	}
	return o.Commit()
}

func (a *app) keysRemove(args []string) error {
	fs := a.newFlags("keys remove", keysHelp)
	var contact, leg, force bool
	fs.BoolVar(&contact, "contact", false, "")
	fs.BoolVar(&leg, "legacy", false, "")
	fs.BoolVar(&force, "f", false, "")
	fs.BoolVar(&force, "force", false, "")
	rest, err := a.parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 || (contact && leg) {
		return usagef("usage: keys remove [--contact|--legacy] NAME")
	}
	name := rest[0]
	kr, err := a.openKeyring()
	if err != nil {
		return err
	}
	kind, what := keys.KindIdentity, "identity"
	switch {
	case contact:
		kind, what = keys.KindContact, "contact"
	case leg:
		kind, what = keys.KindLegacy, "legacy key"
	}
	if kind != keys.KindContact && !force {
		if !confirm(fmt.Sprintf("Permanently delete %s %q? Files encrypted to it can no longer be decrypted.", what, name)) {
			return errors.New("not removed (use --force to remove without asking)")
		}
	}
	if err := kr.Remove(kind, name); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Removed %s %q\n", what, name)
	return nil
}

func (a *app) keysDefault(args []string) error {
	fs := a.newFlags("keys default", keysHelp)
	rest, err := a.parse(fs, args)
	if err != nil {
		return err
	}
	kr, err := a.openKeyring()
	if err != nil {
		return err
	}
	switch len(rest) {
	case 0:
		name, err := kr.DefaultIdentity()
		if err != nil {
			return err
		}
		fmt.Fprintln(a.stdout, name)
		return nil
	case 1:
		return kr.SetDefault(rest[0])
	}
	return usagef("usage: keys default [NAME]")
}

func (a *app) keysPasswd(args []string) error {
	fs := a.newFlags("keys passwd", keysHelp)
	rest, err := a.parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return usagef("usage: keys passwd NAME")
	}
	kr, err := a.openKeyring()
	if err != nil {
		return err
	}
	id, err := kr.LoadIdentity(rest[0], keyUnlocker())
	if err != nil {
		return err
	}
	pass, err := newPassphrase("new passphrase (empty to remove)", true)
	if err != nil {
		return err
	}
	if err := kr.SaveIdentity(id, pass, true); err != nil {
		return err
	}
	if pass == "" {
		fmt.Fprintf(a.stderr, "Identity %q is now stored unlocked\n", id.Name)
	} else {
		fmt.Fprintf(a.stderr, "Passphrase for %q changed\n", id.Name)
	}
	return nil
}

func (a *app) keysPath(args []string) error {
	fs := a.newFlags("keys path", keysHelp)
	if _, err := a.parse(fs, args); err != nil {
		return err
	}
	kr, err := a.openKeyring()
	if err != nil {
		return err
	}
	fmt.Fprintln(a.stdout, kr.Dir)
	return nil
}
