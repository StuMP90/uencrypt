package main

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/StuMP90/uencrypt/internal/envelope"
	"github.com/StuMP90/uencrypt/internal/keys"
	"github.com/StuMP90/uencrypt/internal/legacy"
	"github.com/StuMP90/uencrypt/internal/sign"
)

const encryptHelp = `Usage: uencrypt encrypt [options] FILE...

Encrypts each FILE to FILE.age ("-" reads stdin and writes stdout).
With no -r or -p, files are encrypted to your default identity, which
needs no passphrase at encryption time (suitable for automated backups).

Options:
  -r, --recipient R   encrypt to R: a keyring name, an age1... public key,
                      an SSH public key ("ssh-ed25519 AAAA..."), or a
                      contact or .pub file (repeatable)
  -R FILE             encrypt to every recipient listed in FILE, one per
                      line; ~/.ssh/id_ed25519.pub and authorized_keys
                      files work too (repeatable)
  -p, --passphrase    encrypt with a passphrase instead of keys; read from
                      $UENCRYPT_PASSPHRASE, --passphrase-file or the terminal
      --passphrase-file FILE
                      read the passphrase from the first line of FILE
  -s, --sign          sign the content with your default identity
  -k, --key NAME      sign with identity NAME (implies -s)
  -a, --armor         write ASCII-armored (PEM-style) text
  -o, --output OUT    output file (only with a single input)
  -f, --force         overwrite existing output files
  -q, --quiet         print nothing on success

SSH keys (ssh-ed25519, ssh-rsa) are classic, not post-quantum, so they
cannot be mixed with post-quantum keys in one file.

Signed files need uencrypt to decrypt; plain age tools will output the
signed container instead of the original content.
`

func (a *app) encrypt(args []string) error {
	fs := a.newFlags("encrypt", encryptHelp)
	var recips, recipFiles stringList
	var pass, signFlag, armor, force, quiet bool
	var passFile, keyName, out string
	fs.Var(&recips, "r", "")
	fs.Var(&recips, "recipient", "")
	fs.Var(&recipFiles, "R", "")
	fs.BoolVar(&pass, "p", false, "")
	fs.BoolVar(&pass, "passphrase", false, "")
	fs.StringVar(&passFile, "passphrase-file", "", "")
	fs.BoolVar(&signFlag, "s", false, "")
	fs.BoolVar(&signFlag, "sign", false, "")
	fs.StringVar(&keyName, "k", "", "")
	fs.StringVar(&keyName, "key", "", "")
	fs.BoolVar(&armor, "a", false, "")
	fs.BoolVar(&armor, "armor", false, "")
	fs.StringVar(&out, "o", "", "")
	fs.StringVar(&out, "output", "", "")
	fs.BoolVar(&force, "f", false, "")
	fs.BoolVar(&force, "force", false, "")
	fs.BoolVar(&quiet, "q", false, "")
	fs.BoolVar(&quiet, "quiet", false, "")
	files, err := a.parse(fs, args)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return usagef("no input files (use - for stdin)")
	}
	if out != "" && len(files) > 1 {
		return usagef("-o can only be used with a single input file")
	}
	pass = pass || passFile != ""
	if pass && (len(recips) > 0 || len(recipFiles) > 0) {
		return usagef("use either recipients (-r/-R) or a passphrase (-p), not both")
	}

	opts := envelope.EncryptOptions{Armor: armor}
	var toNames []string
	if pass {
		if opts.Passphrase, err = encryptPassphrase(passFile); err != nil {
			return err
		}
	} else {
		var classic []string
		if opts.Recipients, toNames, classic, err = a.resolveRecipients(recips, recipFiles); err != nil {
			return err
		}
		if len(classic) > 0 && len(classic) < len(toNames) {
			return fmt.Errorf("cannot mix post-quantum and classic recipients in one file (classic: %s); "+
				"ask them for a post-quantum key or encrypt separate copies", strings.Join(classic, ", "))
		}
		if len(classic) > 0 && !quiet {
			a.warnf("recipients use classic (non post-quantum) keys")
		}
	}
	if signFlag || keyName != "" {
		id, err := a.loadSigningIdentity(keyName)
		if err != nil {
			return err
		}
		opts.Signer = id.Signer
	}

	for _, in := range files {
		dst := out
		if dst == "" {
			dst = encryptedName(in)
			if in == "-" {
				dst = "-"
			}
		}
		if err := a.encryptFile(in, dst, force, opts); err != nil {
			return fmt.Errorf("%s: %w", in, err)
		}
		if !quiet && dst != "-" {
			to := "passphrase"
			if !pass {
				to = strings.Join(toNames, ", ")
			}
			fmt.Fprintf(a.stderr, "%s -> %s (to %s%s)\n", in, dst, to, map[bool]string{true: ", signed"}[opts.Signer != nil])
		}
	}
	return nil
}

func (a *app) encryptFile(in, dst string, force bool, opts envelope.EncryptOptions) error {
	r, err := openInput(in)
	if err != nil {
		return err
	}
	defer r.Close()
	o, err := createOutput(dst, force, !opts.Armor, 0o644)
	if err != nil {
		return err
	}
	defer o.Abort()
	if err := envelope.Encrypt(a.ctx, r, o, opts); err != nil {
		return err
	}
	return o.Commit()
}

// resolveRecipients turns -r and -R arguments into age recipients. It
// returns display names and the names of classic (non-PQ) recipients.
func (a *app) resolveRecipients(rs, files []string) ([]age.Recipient, []string, []string, error) {
	var out []age.Recipient
	var names, classic []string
	add := func(name string, r age.Recipient) {
		out = append(out, r)
		names = append(names, name)
		if keys.StanzaType(r) != "mlkem768x25519" {
			classic = append(classic, name)
		}
	}
	if len(rs) == 0 && len(files) == 0 {
		kr, err := a.openKeyring()
		if err != nil {
			return nil, nil, nil, err
		}
		name, err := kr.DefaultIdentity()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%w (or use -r/-p)", err)
		}
		c, err := kr.IdentityPublic(name)
		if err != nil {
			return nil, nil, nil, err
		}
		add(name, c.Recipient)
		return out, names, classic, nil
	}
	for _, r := range rs {
		c, err := a.resolveRecipient(r)
		if err != nil {
			return nil, nil, nil, err
		}
		add(c.Name, c.Recipient)
	}
	for _, f := range files {
		data, err := readSmallFile(f)
		if err != nil {
			return nil, nil, nil, err
		}
		list, err := keys.ParseRecipientsFile(data)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s: %w", f, err)
		}
		for i, r := range list {
			add(fmt.Sprintf("%s#%d", f, i+1), r)
		}
	}
	return out, names, classic, nil
}

// resolveRecipient accepts an age1... or SSH key, a keyring name or a
// contact file.
func (a *app) resolveRecipient(s string) (*keys.Contact, error) {
	if keys.IsSSHRecipient(s) {
		c, err := keys.ParseContact([]byte(s))
		if err != nil {
			return nil, err
		}
		if c.Name == "" {
			c.Name = strings.Fields(c.RecipientString)[0]
		}
		return c, nil
	}
	if strings.HasPrefix(s, "age1") {
		r, err := keys.ParseRecipient(s)
		if err != nil {
			return nil, err
		}
		short := s
		if len(short) > 20 {
			short = short[:12] + "..." + short[len(short)-6:]
		}
		return &keys.Contact{Name: short, Recipient: r, RecipientString: s}, nil
	}
	if keys.ValidateName(s) == nil {
		kr, err := a.openKeyring()
		if err != nil {
			return nil, err
		}
		c, err := kr.Recipient(s)
		if err == nil {
			return c, nil
		}
		if !errors.Is(err, keys.ErrNotFound) {
			return nil, err
		}
	}
	data, err := readSmallFile(s)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("recipient %q: not a public key, keyring name or file", s)
	}
	if err != nil {
		return nil, err
	}
	c, err := keys.ParseContact(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s, err)
	}
	if c.Name == "" {
		c.Name = s
	}
	return c, nil
}

// encryptPassphrase gets the passphrase for encrypt -p.
func encryptPassphrase(file string) (string, error) {
	if file != "" {
		b, err := readSmallFile(file)
		if err != nil {
			return "", err
		}
		p, _, _ := strings.Cut(string(b), "\n")
		p = strings.TrimSuffix(p, "\r")
		if p == "" {
			return "", errors.New(file + ": empty passphrase")
		}
		return p, nil
	}
	if p, ok := os.LookupEnv("UENCRYPT_PASSPHRASE"); ok {
		if p == "" {
			return "", errors.New("UENCRYPT_PASSPHRASE is empty")
		}
		return p, nil
	}
	p, err := newPassphrase("passphrase", false)
	if errors.Is(err, errNoTTY) {
		return "", errors.New("no passphrase: set UENCRYPT_PASSPHRASE, use --passphrase-file, or run in a terminal")
	}
	return p, err
}

// loadSigningIdentity loads the named (or default) identity's signing key.
func (a *app) loadSigningIdentity(name string) (*keys.Identity, error) {
	kr, err := a.openKeyring()
	if err != nil {
		return nil, err
	}
	if name == "" {
		if name, err = kr.DefaultIdentity(); err != nil {
			return nil, err
		}
	}
	id, err := kr.LoadIdentity(name, keyUnlocker())
	if err != nil {
		return nil, err
	}
	if id.Signer == nil {
		return nil, fmt.Errorf("identity %q has no signing key (it was imported from a plain age key file)", name)
	}
	return id, nil
}

const decryptHelp = `Usage: uencrypt decrypt [options] FILE...

Decrypts each FILE: age files (.age, from uencrypt or any age tool) and
files from the old ppkencrypt/oakcryptor tools (.enc). The output name
drops .age/.enc, or otherwise inserts .dec before the extension.
"-" reads stdin and writes stdout.

Keys in the keyring are tried automatically; locked keys are unlocked
only if the file is encrypted to them.

Options:
  -i, --identity FILE   also try the age identity file or SSH private key
                        FILE (repeatable)
      --legacy-key PEM  also try the old RSA private key PEM (repeatable)
      --signer NAME     require a valid signature by NAME (a contact or
                        your own identity); fails with exit status 3
  -o, --output OUT      output file (only with a single input)
  -f, --force           overwrite existing output files
  -q, --quiet           print nothing on success

Files are written under a temporary name and only renamed once fully
decrypted and verified. When writing to stdout, data is streamed and
the exit status must be checked.
`

func (a *app) decrypt(args []string) error {
	fs := a.newFlags("decrypt", decryptHelp)
	var idFiles, legacyFiles stringList
	var signer, out string
	var force, quiet bool
	fs.Var(&idFiles, "i", "")
	fs.Var(&idFiles, "identity", "")
	fs.Var(&legacyFiles, "legacy-key", "")
	fs.StringVar(&signer, "signer", "", "")
	fs.StringVar(&out, "o", "", "")
	fs.StringVar(&out, "output", "", "")
	fs.BoolVar(&force, "f", false, "")
	fs.BoolVar(&force, "force", false, "")
	fs.BoolVar(&quiet, "q", false, "")
	fs.BoolVar(&quiet, "quiet", false, "")
	files, err := a.parse(fs, args)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return usagef("no input files (use - for stdin)")
	}
	if out != "" && len(files) > 1 {
		return usagef("-o can only be used with a single input file")
	}

	kr, err := a.openKeyring()
	if err != nil {
		return err
	}
	var want *sign.PublicKey
	if signer != "" {
		c, err := kr.Recipient(signer)
		if err != nil {
			return err
		}
		if c.Signer == nil {
			return fmt.Errorf("%q has no signing key", signer)
		}
		want = c.Signer
	}

	opts, err := a.decryptOptions(kr, idFiles, legacyFiles, quiet)
	if err != nil {
		return err
	}

	for _, in := range files {
		dst := out
		if dst == "" {
			dst = decryptedName(in)
			if in == "-" {
				dst = "-"
			}
		}
		if err := a.decryptFile(kr, in, dst, force, quiet, want, opts); err != nil {
			return fmt.Errorf("%s: %w", in, err)
		}
	}
	return nil
}

// decryptOptions gathers the keys a file may be decrypted with: identity
// files given with -i, the keyring's identities, the standard SSH keys,
// imported legacy keys and those given with --legacy-key, and a
// passphrase prompt.
func (a *app) decryptOptions(kr *keys.Keyring, idFiles, legacyFiles []string, quiet bool) (envelope.DecryptOptions, error) {
	var ids []age.Identity
	for _, f := range idFiles {
		list, err := readIdentityFile(f)
		if err != nil {
			return envelope.DecryptOptions{}, err
		}
		ids = append(ids, list...)
	}
	krIDs, err := kr.DecryptionIdentities(keyUnlocker())
	if err != nil {
		return envelope.DecryptOptions{}, err
	}
	ids = append(ids, krIDs...)
	// Like age, uencrypt tries the standard SSH keys, but only for files
	// encrypted to an SSH key.
	ids = append(ids, keys.DefaultSSHIdentities(sshPassphrase)...)

	var extraLegacy []*rsa.PrivateKey
	for _, f := range legacyFiles {
		data, err := readSmallFile(f)
		if err != nil {
			return envelope.DecryptOptions{}, err
		}
		k, err := legacy.ParsePrivateKey(data)
		if err != nil {
			return envelope.DecryptOptions{}, fmt.Errorf("%s: %w", f, err)
		}
		extraLegacy = append(extraLegacy, k)
	}
	return envelope.DecryptOptions{
		Identities: ids,
		Passphrase: filePassphrase(),
		LegacyKeys: func() ([]*rsa.PrivateKey, error) {
			ks, err := kr.LegacyKeys()
			if err != nil && !quiet {
				a.warnf("%v", err)
			}
			return append(extraLegacy, ks...), nil
		},
	}, nil
}

func (a *app) decryptFile(kr *keys.Keyring, in, dst string, force, quiet bool, want *sign.PublicKey, opts envelope.DecryptOptions) error {
	r, err := openInput(in)
	if err != nil {
		return err
	}
	defer r.Close()
	o, err := createOutput(dst, force, false, 0o600)
	if err != nil {
		return err
	}
	defer o.Abort()
	res, err := envelope.Decrypt(a.ctx, r, o, opts)
	if res != nil && res.Signer != nil && errors.Is(err, sign.ErrBadSignature) {
		return fmt.Errorf("%w (claimed signer %s)", err, a.describeSigner(kr, res.Signer))
	}
	if err != nil {
		return err
	}
	if want != nil {
		switch {
		case !res.Signed:
			return fmt.Errorf("%w: file is not signed", errSignature)
		case !res.Signer.Equal(want):
			return fmt.Errorf("%w: signed by %s, not the required signer", errSignature, a.describeSigner(kr, res.Signer))
		}
	}
	if err := o.Commit(); err != nil {
		return err
	}
	for _, w := range res.Warnings {
		a.warnf("%s: %s", in, w)
	}
	if res.Signed {
		a.reportSignature(kr, res.Signer, res.SignedAt, quiet)
	}
	if !quiet && dst != "-" {
		fmt.Fprintf(a.stderr, "%s -> %s (%s)\n", in, dst, res.Format)
	}
	return nil
}

// readIdentityFile reads an age identity file or SSH private key given
// with -i, unlocking it if it is passphrase-protected (an SSH key only
// when a file is encrypted to it).
func readIdentityFile(name string) ([]age.Identity, error) {
	data, err := readSmallFile(name)
	if err != nil {
		return nil, err
	}
	if bytes.Contains(data, []byte("PRIVATE KEY-----")) {
		id, err := keys.ParseSSHIdentity(data, name, sshPassphrase)
		if err != nil {
			return nil, err
		}
		return []age.Identity{id}, nil
	}
	if keys.IsEncrypted(data) {
		for i := 0; ; i++ {
			p, err := readPassword(fmt.Sprintf("Passphrase for %s: ", name))
			if err != nil {
				return nil, fmt.Errorf("%s is passphrase-protected: %w", name, err)
			}
			plain, err := keys.Unlock(data, p)
			if err == nil {
				data = plain
				break
			}
			if !errors.Is(err, keys.ErrBadPassphrase) || i == 2 {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return ids, nil
}

// sshPassphrase asks on the terminal for an SSH key's passphrase.
func sshPassphrase(path string, retry bool) (string, error) {
	if retry {
		fmt.Fprintln(os.Stderr, "Incorrect passphrase, try again.")
	}
	return readPassword(fmt.Sprintf("Passphrase for SSH key %s: ", path))
}

// describeSigner names a signing key: "alice (fp)" or "unknown key fp".
func (a *app) describeSigner(kr *keys.Keyring, pk *sign.PublicKey) string {
	if name, own, ok := kr.SignerName(pk); ok {
		if own {
			return fmt.Sprintf("%s [own key] (%s)", name, pk.Fingerprint())
		}
		return fmt.Sprintf("%s (%s)", name, pk.Fingerprint())
	}
	return "unknown key " + pk.Fingerprint()
}

// reportSignature prints the result of a good signature check. It
// returns false if the signer is not in the keyring.
func (a *app) reportSignature(kr *keys.Keyring, pk *sign.PublicKey, at time.Time, quiet bool) bool {
	_, _, known := kr.SignerName(pk)
	if !known {
		a.warnf("valid signature from %s, which is not in your keyring: "+
			"the signer cannot be confirmed (import their contact card)", a.describeSigner(kr, pk))
		return false
	}
	if !quiet {
		fmt.Fprintf(a.stderr, "Good signature from %s, made %s\n", a.describeSigner(kr, pk), at.Local().Format("2006-01-02 15:04:05 MST"))
	}
	return true
}
