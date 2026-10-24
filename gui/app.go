package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"github.com/wailsapp/wails/v2/pkg/options"

	"github.com/StuMP90/uencrypt/internal/keys"
)

// App is bound to the front end; its exported methods are callable from
// JavaScript. Wails runs each call on its own goroutine, so a long
// operation can block waiting for a prompt that another call answers.
type App struct {
	ctx context.Context

	krOnce sync.Once
	kr     *keys.Keyring
	krErr  error

	// opMu allows one encrypt/decrypt/sign/verify run at a time.
	opMu     sync.Mutex
	cancelMu sync.Mutex
	cancel   context.CancelFunc

	promptMu sync.Mutex
	prompts  map[string]chan promptAnswer
	promptID atomic.Int64

	initial []string

	// lastDir is where the next file dialog opens: the folder of the last
	// file picked, saved or dropped.
	dirMu   sync.Mutex
	lastDir string

	// sshKeys are the SSH private keys chosen for decrypting this session.
	sshMu   sync.Mutex
	sshKeys []string
}

func NewApp() *App {
	return &App{prompts: map[string]chan promptAnswer{}, initial: existingFiles(os.Args[1:])}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.remember(a.initial...)
	wruntime.OnFileDrop(ctx, func(x, y int, paths []string) {
		a.remember(paths...)
		wruntime.EventsEmit(ctx, "files", paths)
	})
}

func (a *App) shutdown(context.Context) { a.Cancel() }

func (a *App) secondInstance(d options.SecondInstanceData) {
	if a.ctx == nil {
		return
	}
	wruntime.WindowUnminimise(a.ctx)
	wruntime.WindowShow(a.ctx)
	if files := existingFiles(d.Args); len(files) > 0 {
		a.remember(files...)
		wruntime.EventsEmit(a.ctx, "files", files)
	}
}

// existingFiles keeps the command-line arguments that are files (as
// passed by a file association).
func existingFiles(args []string) []string {
	var out []string
	for _, p := range args {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			if abs, err := filepath.Abs(p); err == nil {
				p = abs
			}
			out = append(out, p)
		}
	}
	return out
}

// InitialFiles returns the files the app was launched with.
func (a *App) InitialFiles() []string { return a.initial }

func (a *App) Version() string { return version }

func (a *App) keyring() (*keys.Keyring, error) {
	a.krOnce.Do(func() {
		dir, err := keys.DefaultDir()
		if err != nil {
			a.krErr = err
			return
		}
		a.kr, a.krErr = keys.Open(dir)
	})
	return a.kr, a.krErr
}

// --- prompts ---------------------------------------------------------------

// Prompt asks the user something from inside a running operation.
type Prompt struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"` // "passphrase" or "confirm"
	Title   string `json:"title"`
	Message string `json:"message"`
	Error   string `json:"error"`
	// Confirm is the label of the accept button.
	Confirm string `json:"confirm"`
}

type promptAnswer struct {
	value     string
	cancelled bool
}

var errCancelled = errors.New("cancelled")

// ask shows a prompt and waits for AnswerPrompt, or for ctx to end.
func (a *App) ask(ctx context.Context, p Prompt) (string, error) {
	p.ID = strconv.FormatInt(a.promptID.Add(1), 10)
	ch := make(chan promptAnswer, 1)
	a.promptMu.Lock()
	a.prompts[p.ID] = ch
	a.promptMu.Unlock()
	defer func() {
		a.promptMu.Lock()
		delete(a.prompts, p.ID)
		a.promptMu.Unlock()
	}()
	wruntime.EventsEmit(a.ctx, "prompt", p)
	select {
	case ans := <-ch:
		if ans.cancelled {
			return "", errCancelled
		}
		return ans.value, nil
	case <-ctx.Done():
		wruntime.EventsEmit(a.ctx, "prompt-close", p.ID)
		return "", errCancelled
	}
}

// AnswerPrompt is called by the front end to answer a prompt.
func (a *App) AnswerPrompt(id, value string, cancelled bool) {
	a.promptMu.Lock()
	ch := a.prompts[id]
	a.promptMu.Unlock()
	if ch != nil {
		select {
		case ch <- promptAnswer{value: value, cancelled: cancelled}:
		default:
		}
	}
}

func (a *App) confirm(ctx context.Context, title, msg, accept string) bool {
	_, err := a.ask(ctx, Prompt{Kind: "confirm", Title: title, Message: msg, Confirm: accept})
	return err == nil
}

// unlocker asks for the passphrase of locked identities, saying so when a
// retry follows a wrong one.
func (a *App) unlocker(ctx context.Context) *keys.Unlocker {
	tries := map[string]int{}
	return &keys.Unlocker{Ask: func(name string) (string, error) {
		p := Prompt{Kind: "passphrase", Title: "Unlock key", Confirm: "Unlock",
			Message: fmt.Sprintf("Enter the passphrase for your key “%s”.", name)}
		if tries[name] > 0 {
			p.Error = "Incorrect passphrase, try again."
		}
		tries[name]++
		return a.ask(ctx, p)
	}}
}

// --- running operations ----------------------------------------------------

// begin starts an operation, refusing to run two at once.
func (a *App) begin() (context.Context, func(), error) {
	if !a.opMu.TryLock() {
		return nil, nil, errors.New("another operation is still running")
	}
	ctx, cancel := context.WithCancel(a.ctx)
	a.cancelMu.Lock()
	a.cancel = cancel
	a.cancelMu.Unlock()
	return ctx, func() {
		a.cancelMu.Lock()
		a.cancel = nil
		a.cancelMu.Unlock()
		cancel()
		a.opMu.Unlock()
	}, nil
}

// Cancel stops the running operation; its current file is discarded.
func (a *App) Cancel() {
	a.cancelMu.Lock()
	defer a.cancelMu.Unlock()
	if a.cancel != nil {
		a.cancel()
	}
}

// --- dialogs and desktop helpers ------------------------------------------

// remember sets the folder the next dialog opens in from the first path:
// its parent for a file, or itself for a folder.
func (a *App) remember(paths ...string) {
	if len(paths) == 0 || paths[0] == "" {
		return
	}
	dir := paths[0]
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		dir = filepath.Dir(dir)
	}
	a.dirMu.Lock()
	a.lastDir = dir
	a.dirMu.Unlock()
}

// startDir returns the remembered folder if it still exists.
func (a *App) startDir() string {
	a.dirMu.Lock()
	defer a.dirMu.Unlock()
	if st, err := os.Stat(a.lastDir); err == nil && st.IsDir() {
		return a.lastDir
	}
	return ""
}

func (a *App) PickFiles(title string) ([]string, error) {
	paths, err := wruntime.OpenMultipleFilesDialog(a.ctx, wruntime.OpenDialogOptions{Title: title, DefaultDirectory: a.startDir()})
	a.remember(paths...)
	return paths, err
}

func (a *App) PickFile(title string) (string, error) {
	path, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{Title: title, DefaultDirectory: a.startDir()})
	a.remember(path)
	return path, err
}

func (a *App) PickDirectory(title string) (string, error) {
	path, err := wruntime.OpenDirectoryDialog(a.ctx, wruntime.OpenDialogOptions{Title: title, DefaultDirectory: a.startDir(), CanCreateDirectories: true})
	a.remember(path)
	return path, err
}

func (a *App) pickSave(title, name string) (string, error) {
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{Title: title, DefaultDirectory: a.startDir(), DefaultFilename: name})
	a.remember(path)
	return path, err
}

// RevealInFolder opens the file manager at path.
func (a *App) RevealInFolder(path string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// /select opens the parent with path highlighted; a folder is
		// opened itself.
		if st, err := os.Stat(path); err == nil && st.IsDir() {
			cmd = exec.Command("explorer", path)
		} else {
			cmd = exec.Command("explorer", "/select,", path)
		}
	case "darwin":
		cmd = exec.Command("open", "-R", path)
	default:
		if st, err := os.Stat(path); err != nil || !st.IsDir() {
			path = filepath.Dir(path)
		}
		cmd = exec.Command("xdg-open", path)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}

// passChars avoids look-alike characters (0/O, 1/l/I) so a generated
// passphrase can be read out or copied by hand.
const passChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// GeneratePassphrase returns five groups of five random characters
// (about 145 bits).
func (a *App) GeneratePassphrase() string {
	var groups []string
	for range 5 {
		b := make([]byte, 5)
		for i := range b {
			b[i] = passChars[randIndex(len(passChars))]
		}
		groups = append(groups, string(b))
	}
	return strings.Join(groups, "-")
}

// randIndex returns a uniform random number in [0, n) for small n.
func randIndex(n int) int {
	limit := 256 - 256%n
	var b [1]byte
	for {
		rand.Read(b[:])
		if int(b[0]) < limit {
			return int(b[0]) % n
		}
	}
}
