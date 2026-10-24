// Command uencrypt encrypts, decrypts, signs and verifies files with
// post-quantum keys, and decrypts files made by the old ppkencrypt and
// oakcryptor tools.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/StuMP90/uencrypt/internal/envelope"
	"github.com/StuMP90/uencrypt/internal/keys"
	"github.com/StuMP90/uencrypt/internal/sign"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes, documented for scripts.
const (
	exitOK        = 0
	exitError     = 1
	exitUsage     = 2
	exitSignature = 3
	exitNoKey     = 4
)

const usage = `uencrypt - post-quantum file encryption and signing

Usage:
  uencrypt encrypt [-r NAME|KEY|FILE]... [-p] [-s] [-a] [-o OUT] FILE...
  uencrypt decrypt [-i FILE]... [--signer NAME] [-o OUT] FILE...
  uencrypt sign    [-k NAME] [-o OUT] FILE...
  uencrypt verify  [--signer NAME] FILE.sig [FILE]
  uencrypt inspect [--contents] [--json] FILE...
  uencrypt keys    list | new | import | export | remove | default | passwd | path
  uencrypt version

Global options (before the command):
  --keyring DIR   keyring directory (default $UENCRYPT_KEYRING or
                  the user config directory)

Run 'uencrypt COMMAND -h' for a command's options.

Encrypted files are standard age files (.age): with no signature they can be
decrypted by any age v1.3+ tool. Files from ppkencrypt/oakcryptor (.enc) are
decrypted with legacy RSA keys imported by 'uencrypt keys import'.

Environment:
  UENCRYPT_PASSPHRASE      passphrase for -p files (instead of prompting)
  UENCRYPT_KEY_PASSPHRASE  passphrase for locked identities
  UENCRYPT_KEYRING         keyring directory

Exit status: 0 ok, 1 error, 2 usage, 3 signature invalid or missing,
4 no key can decrypt the file.
`

// usageError is reported with exit status 2.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

// errSignature marks a missing, untrusted or mismatched signature (exit 3).
var errSignature = errors.New("signature check failed")

type app struct {
	ctx     context.Context
	keyring string
	kr      *keys.Keyring
	stdout  io.Writer
	stderr  io.Writer
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	a := &app{ctx: ctx, stdout: os.Stdout, stderr: os.Stderr}
	os.Exit(a.run(os.Args[1:]))
}

func (a *app) run(args []string) int {
	global := flag.NewFlagSet("uencrypt", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	global.StringVar(&a.keyring, "keyring", "", "")
	help := global.Bool("help", false, "")
	global.BoolVar(help, "h", false, "")
	if err := global.Parse(args); err != nil {
		fmt.Fprintf(a.stderr, "uencrypt: %v\n\n%s", err, usage)
		return exitUsage
	}
	args = global.Args()
	if *help || len(args) == 0 {
		fmt.Fprint(a.stdout, usage)
		if *help {
			return exitOK
		}
		return exitUsage
	}

	cmds := map[string]func([]string) error{
		"encrypt": a.encrypt,
		"decrypt": a.decrypt,
		"sign":    a.sign,
		"verify":  a.verify,
		"inspect": a.inspect,
		"keys":    a.keys,
		"version": func([]string) error { fmt.Fprintln(a.stdout, "uencrypt", version); return nil },
		"help":    func([]string) error { fmt.Fprint(a.stdout, usage); return nil },
	}
	cmd, ok := cmds[args[0]]
	if !ok {
		fmt.Fprintf(a.stderr, "uencrypt: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
	err := cmd(args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err == nil {
		return exitOK
	}
	fmt.Fprintf(a.stderr, "uencrypt %s: %v\n", args[0], err)
	var ue usageError
	switch {
	case errors.As(err, &ue):
		return exitUsage
	case errors.Is(err, sign.ErrBadSignature), errors.Is(err, errSignature):
		return exitSignature
	case errors.Is(err, envelope.ErrNoKey):
		return exitNoKey
	}
	return exitError
}

// openKeyring opens the keyring on first use.
func (a *app) openKeyring() (*keys.Keyring, error) {
	if a.kr != nil {
		return a.kr, nil
	}
	dir := a.keyring
	if dir == "" {
		var err error
		if dir, err = keys.DefaultDir(); err != nil {
			return nil, err
		}
	}
	kr, err := keys.Open(dir)
	if err != nil {
		return nil, err
	}
	a.kr = kr
	return kr, nil
}

func (a *app) warnf(format string, args ...any) {
	fmt.Fprintf(a.stderr, "warning: "+format+"\n", args...)
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// newFlags makes a flag set whose -h prints the command's help text.
func (a *app) newFlags(name, help string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.Bool("h", false, "")
	fs.Bool("help", false, "")
	fs.Lookup("h").Usage = help
	return fs
}

// parse parses flags that may appear before or after positional
// arguments. Everything after "--" is positional.
func (a *app) parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var tail []string
	for i, arg := range args {
		if arg == "--" {
			args, tail = args[:i], args[i+1:]
			break
		}
	}
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, usagef("%v (see -h)", err)
		}
		if fs.Lookup("h").Value.String() == "true" || fs.Lookup("help").Value.String() == "true" {
			fmt.Fprint(a.stdout, fs.Lookup("h").Usage)
			return nil, flag.ErrHelp
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	return append(pos, tail...), nil
}
