package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"golang.org/x/term"

	"github.com/StuMP90/uencrypt/internal/fileio"
)

// openInput opens a file, or stdin for "-".
func openInput(name string) (io.ReadCloser, error) {
	if name == "-" {
		return io.NopCloser(os.Stdin), nil
	}
	return os.Open(name)
}

// createOutput prepares name ("-" for stdout, which is written directly,
// so pipelines must check the exit status). Unless force is set, an
// existing file is an error. Binary output to a terminal is refused.
func createOutput(name string, force, binary bool, perm fs.FileMode) (*fileio.Output, error) {
	if name == "-" {
		if binary && term.IsTerminal(int(os.Stdout.Fd())) {
			return nil, usagef("refusing to write binary output to a terminal (use -o FILE, or -a for text)")
		}
		return fileio.Stream(os.Stdout), nil
	}
	o, err := fileio.Create(name, force, perm)
	if errors.Is(err, fileio.ErrExists) {
		return nil, fmt.Errorf("%w (use --force to overwrite)", err)
	}
	return o, err
}

var (
	encryptedName = fileio.EncryptedName
	decryptedName = fileio.DecryptedName
	signatureName = fileio.SignatureName
)

// readSmallFile reads a key or signature file ("-" for stdin), refusing
// anything huge.
func readSmallFile(name string) ([]byte, error) {
	f, err := openInput(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return fileio.ReadSmall(f, name)
}
