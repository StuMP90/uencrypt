package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/StuMP90/uencrypt/internal/content"
	"github.com/StuMP90/uencrypt/internal/inspect"
)

const inspectHelp = `Usage: uencrypt inspect [options] FILE...

Describes each FILE without decrypting it or changing anything:
  - age files: the recipient types and how many, whether they resist
    quantum computers, the sizes, and whether one of your keys can open
    it (passphrase files say so; SSH recipients are matched to your
    ~/.ssh keys and SSH contacts; other keys cannot be identified from
    the file, by design)
  - ppkencrypt/oakcryptor .enc files: the format, the RSA key size, the
    chunks, and which imported legacy key opens it
  - signatures (.sig): who signed it and when
  - other files: what they are, listing zip and tar entries

Options:
  -c, --contents        also decrypt in memory (nothing is saved) to show
                        what the file holds and whether it is signed;
                        asks for passphrases as decrypt does
  -i, --identity FILE   with --contents, an extra identity or SSH key
                        (repeatable)
      --legacy-key FILE an extra legacy RSA key (repeatable)
      --json            print a JSON array, one object per file
`

func (a *app) inspect(args []string) error {
	fs := a.newFlags("inspect", inspectHelp)
	var idFiles, legacyFiles stringList
	var contents, asJSON bool
	fs.BoolVar(&contents, "c", false, "")
	fs.BoolVar(&contents, "contents", false, "")
	fs.Var(&idFiles, "i", "")
	fs.Var(&idFiles, "identity", "")
	fs.Var(&legacyFiles, "legacy-key", "")
	fs.BoolVar(&asJSON, "json", false, "")
	files, err := a.parse(fs, args)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return usagef("no input files")
	}
	kr, err := a.openKeyring()
	if err != nil {
		return err
	}
	opts := inspect.Options{Keyring: kr, SSHKeys: idFiles, Contents: contents}
	// Identity files are only read (and perhaps unlocked) to decrypt.
	if !contents {
		idFiles = nil
	}
	if opts.Decrypt, err = a.decryptOptions(kr, idFiles, legacyFiles, false); err != nil {
		return err
	}

	type entry struct {
		*inspect.Report
		Path  string `json:"path"` // also when the file could not be inspected
		Error string `json:"error,omitempty"`
	}
	var out []entry
	var failed error
	for i, name := range files {
		var rep *inspect.Report
		err := errors.New("inspect needs a file, not standard input")
		if name != "-" {
			rep, err = inspect.File(a.ctx, name, opts)
		}
		if err != nil {
			failed = errors.New("some files could not be inspected")
			if asJSON {
				out = append(out, entry{Path: name, Error: err.Error()})
			} else {
				fmt.Fprintf(a.stderr, "%s: %v\n", name, err)
			}
			continue
		}
		if asJSON {
			out = append(out, entry{Report: rep, Path: rep.Path})
			continue
		}
		if i > 0 {
			fmt.Fprintln(a.stdout)
		}
		printReport(a.stdout, rep, contents)
	}
	if asJSON {
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return err
		}
	}
	return failed
}

// listLimit is how many archive entries the text report lists.
const listLimit = 50

func printReport(w io.Writer, r *inspect.Report, contents bool) {
	line := func(label, format string, args ...any) {
		fmt.Fprintf(w, "  %-18s %s\n", label+":", fmt.Sprintf(format, args...))
	}
	fmt.Fprintf(w, "%s:\n", r.Path)
	if r.Kind == "plain" {
		line("Type", "%s, not encrypted", r.Content.Description)
		line("Size", "%s", byteSize(r.FileSize))
		printContent(w, line, r.Content, false)
		return
	}
	line("Type", "%s", r.Format)
	if r.Kind == "signature" {
		line("Signer", "%s", r.Signature.Describe())
		line("Signed at", "%s", r.Signature.SignedAt.Local().Format("2006-01-02 15:04:05 MST"))
		return
	}
	line("Encryption", "%s", r.Encryption)
	for i, rc := range r.Recipients {
		label := ""
		if i == 0 {
			label = "Recipients"
		}
		var who []string
		who = append(who, rc.Keys...)
		if rc.Unidentified > 0 && rc.Type != "scrypt" {
			who = append(who, fmt.Sprintf("%d not identifiable", rc.Unidentified))
		}
		desc := fmt.Sprintf("%d × %s", rc.Count, rc.Description)
		if len(who) > 0 {
			desc += " (" + strings.Join(who, ", ") + ")"
		}
		if label == "" {
			fmt.Fprintf(w, "  %-18s %s\n", "", desc)
		} else {
			line(label, "%s", desc)
		}
	}
	if l := r.Legacy; l != nil && l.Chunks > 0 {
		each := ""
		if l.Chunks > 1 {
			each = " each (the last may be smaller)"
		}
		line("Chunks", "%d of %s%s", l.Chunks, byteSize(l.ChunkSize), each)
	}
	line("Quantum-resistant", "%s", yesNo(r.PostQuantum))
	line("For you", "%s", r.Access)
	if s := r.Sizes; s != nil {
		armored := ""
		if r.Armored {
			armored = fmt.Sprintf("; the armored file is %s", byteSize(r.FileSize))
		}
		// The payload includes the signature of a signed file.
		line("Sizes", "payload %s + overhead %s (of which header %s) = %s%s",
			byteSize(s.Payload), byteSize(s.Overhead), byteSize(s.Header), byteSize(s.Total), armored)
	}
	switch {
	case r.Signed != nil && *r.Signed:
		line("Signed", "yes, by %s at %s", r.Signature.Describe(), r.Signature.SignedAt.Local().Format("2006-01-02 15:04:05 MST"))
	case r.Signed != nil:
		line("Signed", "no")
	case r.Kind == "age" && !contents:
		line("Signed", "unknown until decrypted (use --contents)")
	}
	if contents {
		if r.ContentsError != "" {
			line("Contents", "could not decrypt: %s", r.ContentsError)
		} else {
			printContent(w, line, r.Content, true)
		}
	}
	for _, warn := range r.Warnings {
		line("Warning", "%s", warn)
	}
}

func printContent(w io.Writer, line func(string, string, ...any), c *content.Report, decrypted bool) {
	if decrypted {
		line("Contents", "%s, %s", c.Description, byteSize(c.Size))
	}
	if c.Uncompressed > 0 {
		line("Uncompressed", "%s", byteSize(c.Uncompressed))
	}
	if c.Archive {
		line("Entries", "%d", c.EntryCount)
		for i, e := range c.Entries {
			if i == listLimit {
				fmt.Fprintf(w, "    ... and %d more (--json lists up to %d)\n", c.EntryCount-listLimit, content.MaxEntries)
				break
			}
			when := "                "
			if !e.Modified.IsZero() {
				when = e.Modified.Local().Format("2006-01-02 15:04")
			}
			size := byteSize(e.Size)
			if e.Dir {
				size = "folder"
			}
			fmt.Fprintf(w, "    %s %10s  %s\n", when, size, e.Name)
		}
	}
	for _, n := range c.Notes {
		line("Note", "%s", n)
	}
}

func byteSize(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	f, unit := float64(n), ""
	for _, u := range []string{"KiB", "MiB", "GiB", "TiB"} {
		f, unit = f/1024, u
		if f < 1024 {
			break
		}
	}
	return fmt.Sprintf("%.1f %s", f, unit)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
