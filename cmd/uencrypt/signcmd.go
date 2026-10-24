package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/StuMP90/uencrypt/internal/sign"
)

const signHelp = `Usage: uencrypt sign [options] FILE...

Writes a detached signature FILE.sig for each FILE, using a hybrid
post-quantum (ML-DSA-65 + Ed25519) signing key. The file itself is
not changed; send FILE and FILE.sig together.

Options:
  -k, --key NAME     sign with identity NAME (default: the default identity)
  -o, --output OUT   signature file (only with a single input; "-" = stdout)
  -f, --force        overwrite existing signature files
  -q, --quiet        print nothing on success
`

func (a *app) sign(args []string) error {
	fs := a.newFlags("sign", signHelp)
	var keyName, out string
	var force, quiet bool
	fs.StringVar(&keyName, "k", "", "")
	fs.StringVar(&keyName, "key", "", "")
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
	id, err := a.loadSigningIdentity(keyName)
	if err != nil {
		return err
	}
	for _, in := range files {
		dst := out
		if dst == "" {
			dst = signatureName(in)
			if in == "-" {
				dst = "-"
			}
		}
		if err := a.signFile(id.Signer, in, dst, force); err != nil {
			return fmt.Errorf("%s: %w", in, err)
		}
		if !quiet && dst != "-" {
			fmt.Fprintf(a.stderr, "%s -> %s (signed by %s)\n", in, dst, id.Name)
		}
	}
	return nil
}

func (a *app) signFile(sk *sign.SecretKey, in, dst string, force bool) error {
	r, err := openInput(in)
	if err != nil {
		return err
	}
	defer r.Close()
	sig, err := sign.SignDetached(sk, r, time.Now())
	if err != nil {
		return err
	}
	o, err := createOutput(dst, force, false, 0o644)
	if err != nil {
		return err
	}
	defer o.Abort()
	if _, err := o.Write(sig); err != nil {
		return err
	}
	return o.Commit()
}

const verifyHelp = `Usage: uencrypt verify [options] FILE.sig [FILE]

Checks a detached signature. FILE defaults to FILE.sig without ".sig".
The signer must be in your keyring (a contact or your own identity)
unless --any is given.

Options:
      --signer NAME   require the signature to be by NAME
      --any           accept a valid signature from an unknown key
  -q, --quiet         print nothing on success

Exit status 3 means the signature is invalid, or not by a known or
required signer.
`

func (a *app) verify(args []string) error {
	fs := a.newFlags("verify", verifyHelp)
	var signer string
	var anyKey, quiet bool
	fs.StringVar(&signer, "signer", "", "")
	fs.BoolVar(&anyKey, "any", false, "")
	fs.BoolVar(&quiet, "q", false, "")
	fs.BoolVar(&quiet, "quiet", false, "")
	files, err := a.parse(fs, args)
	if err != nil {
		return err
	}
	var sigFile, content string
	switch len(files) {
	case 1:
		sigFile = files[0]
		if !strings.HasSuffix(sigFile, ".sig") {
			return usagef("give the signed file as well: verify FILE.sig FILE")
		}
		content = strings.TrimSuffix(sigFile, ".sig")
	case 2:
		sigFile, content = files[0], files[1]
	default:
		return usagef("expected FILE.sig [FILE]")
	}
	if sigFile == "-" && content == "-" {
		return usagef("the signature and the file cannot both be stdin")
	}

	kr, err := a.openKeyring()
	if err != nil {
		return err
	}
	sigText, err := readSmallFile(sigFile)
	if err != nil {
		return err
	}
	r, err := openInput(content)
	if err != nil {
		return err
	}
	defer r.Close()
	h, err := sign.VerifyDetached(sigText, r)
	if err != nil {
		return err
	}
	if signer != "" {
		c, err := kr.Recipient(signer)
		if err != nil {
			return err
		}
		if c.Signer == nil || !c.Signer.Equal(h.Signer) {
			return fmt.Errorf("%w: signed by %s, not %s", errSignature, a.describeSigner(kr, h.Signer), signer)
		}
	}
	if a.reportSignature(kr, h.Signer, h.Created, quiet) || anyKey || signer != "" {
		return nil
	}
	return fmt.Errorf("%w: signer is not in your keyring (use --any to accept it)", errSignature)
}
