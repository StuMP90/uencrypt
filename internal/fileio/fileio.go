// Package fileio holds the file handling shared by the CLI and the GUI:
// outputs that only appear once complete, and default output names.
package fileio

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ErrExists is returned by Create when the output exists and force is off.
var ErrExists = errors.New("already exists")

// Output is a file that only appears under its final name once the
// operation succeeded: it is written to a temporary file in the same
// directory and renamed by Commit.
type Output struct {
	io.Writer
	name string
	tmp  *os.File
	perm fs.FileMode
	done bool
}

// Create prepares name. Unless force is set, an existing file is an error
// wrapping ErrExists.
func Create(name string, force bool, perm fs.FileMode) (*Output, error) {
	if !force {
		if _, err := os.Lstat(name); err == nil {
			return nil, fmt.Errorf("%s %w", name, ErrExists)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), "."+filepath.Base(name)+".*.tmp")
	if err != nil {
		return nil, err
	}
	return &Output{Writer: tmp, name: name, tmp: tmp, perm: perm}, nil
}

// Stream wraps a writer that cannot be made atomic, such as stdout.
// Commit and Abort do nothing.
func Stream(w io.Writer) *Output { return &Output{Writer: w, name: "-"} }

// Name is the final file name.
func (o *Output) Name() string { return o.name }

// Commit moves the finished file into place.
func (o *Output) Commit() error {
	if o.tmp == nil {
		return nil
	}
	o.done = true
	if err := o.tmp.Close(); err != nil {
		os.Remove(o.tmp.Name())
		return err
	}
	if err := os.Chmod(o.tmp.Name(), o.perm); err != nil {
		os.Remove(o.tmp.Name())
		return err
	}
	if err := os.Rename(o.tmp.Name(), o.name); err != nil {
		os.Remove(o.tmp.Name())
		return err
	}
	return nil
}

// Abort discards an uncommitted file; it is safe to defer.
func (o *Output) Abort() {
	if o.tmp == nil || o.done {
		return
	}
	o.done = true
	o.tmp.Close()
	os.Remove(o.tmp.Name())
}

// EncryptedName is the default output for encrypting in.
func EncryptedName(in string) string { return in + ".age" }

// DecryptedName is the default output for decrypting in: .age and .enc
// are removed, otherwise ".dec" goes before the extension (as ppkdecrypt
// did), so the input is never overwritten.
func DecryptedName(in string) string {
	lower := strings.ToLower(in)
	for _, ext := range []string{".age", ".enc"} {
		if strings.HasSuffix(lower, ext) && len(in) > len(ext) {
			if base := in[:len(in)-len(ext)]; !strings.HasSuffix(base, string(filepath.Separator)) && !strings.HasSuffix(base, "/") {
				return base
			}
		}
	}
	ext := filepath.Ext(in)
	return strings.TrimSuffix(in, ext) + ".dec" + ext
}

// SignatureName is the default detached signature for in.
func SignatureName(in string) string { return in + ".sig" }

// MaxSmall is the size limit for key and signature files.
const MaxSmall = 1 << 20

// ReadSmall reads a key or signature, refusing anything huge.
func ReadSmall(r io.Reader, name string) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxSmall+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxSmall {
		return nil, errors.New(name + ": file too large for a key or signature")
	}
	return b, nil
}

// ReadSmallFile is ReadSmall for a named file.
func ReadSmallFile(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadSmall(f, name)
}
