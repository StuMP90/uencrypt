// Package content identifies what a stream of data is (a zip, a tar.gz, a
// PDF, text...) and lists the entries of the archives it can read, without
// keeping the data. It is used to describe plain files and, in memory, what
// an encrypted file holds.
package content

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// MaxEntries is how many archive entries a Report lists; the rest are only
// counted.
const MaxEntries = 1000

// zipTail is how much of the end of a zip is kept to read its central
// directory from (its list of entries). Zips whose directory is larger are
// identified but not listed.
const zipTail = 16 << 20

const sniffLen = 512

// Entry is one file or folder in an archive.
type Entry struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified,omitzero"`
	Dir      bool      `json:"dir,omitempty"`
}

// Report describes the data written to an Analyzer.
type Report struct {
	// Type is a short identifier such as "zip", "tar.gz", "pdf", "text"
	// or "binary".
	Type        string `json:"type"`
	Description string `json:"description"`
	Size        int64  `json:"size"`
	// Archive is true for types whose entries can be listed.
	Archive bool    `json:"archive,omitempty"`
	Entries []Entry `json:"entries,omitempty"`
	// EntryCount is the number of entries, which may be more than listed.
	EntryCount int `json:"entryCount,omitempty"`
	// Uncompressed is the size inside gzip or bzip2 compression.
	Uncompressed int64    `json:"uncompressed,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

// Analyzer is written the data, then closed to produce its Report.
type Analyzer struct {
	head    []byte
	size    int64
	decided bool
	rep     Report

	// tar, gzip and bzip2 are parsed as a stream on another goroutine.
	pw   *io.PipeWriter
	done chan struct{}

	// zip keeps the end of the data.
	zip  bool
	tail []byte
}

// New returns an Analyzer.
func New() *Analyzer { return &Analyzer{} }

// Analyze reads r to the end and reports what it is.
func Analyze(r io.Reader) (*Report, error) {
	a := New()
	if _, err := io.Copy(a, r); err != nil {
		a.Close()
		return nil, err
	}
	return a.Close()
}

func (a *Analyzer) Write(p []byte) (int, error) {
	n := len(p)
	a.size += int64(n)
	if !a.decided {
		take := min(sniffLen-len(a.head), len(p))
		a.head = append(a.head, p[:take]...)
		if len(a.head) < sniffLen {
			return n, nil
		}
		a.decide()
		a.feed(a.head)
		p = p[take:]
	}
	a.feed(p)
	return n, nil
}

func (a *Analyzer) feed(p []byte) {
	switch {
	case a.pw != nil:
		a.pw.Write(p)
	case a.zip:
		a.tail = append(a.tail, p...)
		if len(a.tail) > 2*zipTail {
			a.tail = append(a.tail[:0], a.tail[len(a.tail)-zipTail:]...)
		}
	}
}

// Close finishes the analysis.
func (a *Analyzer) Close() (*Report, error) {
	if !a.decided {
		a.decide()
		a.feed(a.head)
	}
	if a.pw != nil {
		a.pw.Close()
		<-a.done
		a.pw = nil
	}
	if a.zip {
		a.listZip()
		a.zip, a.tail = false, nil
	}
	a.rep.Size = a.size
	if a.rep.Archive && a.rep.EntryCount > len(a.rep.Entries) {
		a.rep.Notes = append(a.rep.Notes, fmt.Sprintf("only the first %d entries are listed", len(a.rep.Entries)))
	}
	return &a.rep, nil
}

type magic struct {
	offset    int
	sig, typ  string
	desc      string
	streaming func(a *Analyzer, r io.Reader)
}

// magics is set in init: its streaming readers analyse nested data, which
// refers back to it.
var magics []magic

func init() {
	magics = []magic{
		{0, "PK\x03\x04", "zip", "zip archive", nil},
		{0, "PK\x05\x06", "zip", "zip archive", nil},
		{0, "PK\x07\x08", "zip", "zip archive", nil},
		{0, "\x1f\x8b", "gzip", "gzip-compressed data", readGzip},
		{0, "BZh", "bzip2", "bzip2-compressed data", readBzip2},
		{257, "ustar", "tar", "tar archive", readTar},
		{0, "\xfd7zXZ\x00", "xz", "xz-compressed data", nil},
		{0, "\x28\xb5\x2f\xfd", "zstd", "zstd-compressed data", nil},
		{0, "7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive (entries are not listed)", nil},
		{0, "Rar!\x1a\x07", "rar", "RAR archive (entries are not listed)", nil},
		{0, "age-encryption.org/", "age", "age encrypted file", nil},
		{0, "-----BEGIN AGE ENCRYPTED FILE-----", "age", "age encrypted file (armored)", nil},
		{0, "%PDF-", "pdf", "PDF document", nil},
		{0, "\x89PNG\r\n\x1a\n", "png", "PNG image", nil},
		{0, "\xff\xd8\xff", "jpeg", "JPEG image", nil},
		{0, "GIF8", "gif", "GIF image", nil},
		{0, "SQLite format 3\x00", "sqlite", "SQLite database", nil},
		{0, "\x7fELF", "elf", "Linux/Unix executable (ELF)", nil},
		{0, "MZ", "exe", "Windows executable", nil},
	}
}

// decide identifies the data from its first bytes.
func (a *Analyzer) decide() {
	a.decided = true
	h := a.head
	if len(h) == 0 {
		a.rep.Type, a.rep.Description = "empty", "empty"
		return
	}
	for _, m := range magics {
		if len(h) >= m.offset+len(m.sig) && string(h[m.offset:m.offset+len(m.sig)]) == m.sig {
			a.rep.Type, a.rep.Description = m.typ, m.desc
			switch {
			case m.typ == "zip":
				a.rep.Archive, a.zip = true, true
			case m.streaming != nil:
				a.stream(m.streaming)
			}
			return
		}
	}
	if label, ok := pemLabel(h); ok {
		a.rep.Type, a.rep.Description = "pem", "PEM text ("+strings.ToLower(label)+")"
		return
	}
	if isText(h) {
		a.rep.Type, a.rep.Description = "text", "text"
		return
	}
	ct := http.DetectContentType(h)
	if ct == "application/octet-stream" {
		a.rep.Type, a.rep.Description = "binary", "binary data (type not recognised)"
		return
	}
	a.rep.Type, a.rep.Description = ct, ct
}

func (a *Analyzer) stream(fn func(*Analyzer, io.Reader)) {
	pr, pw := io.Pipe()
	a.pw, a.done = pw, make(chan struct{})
	go func() {
		defer close(a.done)
		fn(a, pr)
		// Always drain, so writes never block.
		io.Copy(io.Discard, pr)
	}()
}

func (a *Analyzer) note(format string, args ...any) {
	a.rep.Notes = append(a.rep.Notes, fmt.Sprintf(format, args...))
}

func (a *Analyzer) add(e Entry) {
	a.rep.EntryCount++
	if len(a.rep.Entries) < MaxEntries {
		a.rep.Entries = append(a.rep.Entries, e)
	}
}

func readTar(a *Analyzer, r io.Reader) {
	a.rep.Archive = true
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			a.note("the archive is damaged after %d entries: %v", a.rep.EntryCount, err)
			return
		}
		a.add(Entry{Name: h.Name, Size: h.Size, Modified: h.ModTime, Dir: h.Typeflag == tar.TypeDir})
	}
}

func readGzip(a *Analyzer, r io.Reader) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		a.note("the gzip data is damaged: %v", err)
		return
	}
	a.compressed(gz, "gzip", gz.Name)
}

func readBzip2(a *Analyzer, r io.Reader) {
	a.compressed(bzip2.NewReader(r), "bzip2", "")
}

// compressed analyses decompressed data, so a .tar.gz lists its entries.
func (a *Analyzer) compressed(r io.Reader, kind, name string) {
	inner := New()
	_, err := io.Copy(inner, r)
	in, _ := inner.Close()
	a.rep.Uncompressed = in.Size
	if err != nil {
		a.note("the %s data is damaged: %v", kind, err)
	}
	switch {
	case in.Type == "tar":
		a.rep.Type = "tar." + map[string]string{"gzip": "gz", "bzip2": "bz2"}[kind]
		a.rep.Description = "tar archive, " + kind + "-compressed"
		a.rep.Archive = true
		a.rep.Entries, a.rep.EntryCount = in.Entries, in.EntryCount
	case in.Size > 0:
		a.rep.Description = fmt.Sprintf("%s-compressed %s", kind, in.Description)
	}
	if name != "" {
		a.note("original file name: %s", name)
	}
	a.rep.Notes = append(a.rep.Notes, in.Notes...)
}

// listZip reads the central directory from the kept tail of the data.
func (a *Analyzer) listZip() {
	ra := &tailReader{tail: a.tail, start: a.size - int64(len(a.tail))}
	zr, err := zip.NewReader(ra, a.size)
	if err != nil {
		if errors.Is(err, errOutsideTail) {
			a.note("the zip has too many entries to list")
		} else {
			a.note("the zip is damaged: %v", err)
		}
		return
	}
	for _, f := range zr.File {
		a.add(Entry{Name: f.Name, Size: int64(f.UncompressedSize64), Modified: f.Modified, Dir: f.FileInfo().IsDir()})
	}
	if d := officeType(zr.File); d != "" {
		a.rep.Description = d + " (a zip archive)"
	}
}

// officeType recognises document formats that are zips.
func officeType(files []*zip.File) string {
	for _, f := range files {
		switch f.Name {
		case "word/document.xml":
			return "Word document"
		case "xl/workbook.xml":
			return "Excel workbook"
		case "ppt/presentation.xml":
			return "PowerPoint presentation"
		case "META-INF/MANIFEST.MF":
			return "Java archive"
		case "AndroidManifest.xml":
			return "Android app"
		}
	}
	if len(files) > 0 && files[0].Name == "mimetype" {
		return "OpenDocument file"
	}
	return ""
}

var errOutsideTail = errors.New("outside the kept data")

// tailReader is a ReaderAt that holds only the end of the data.
type tailReader struct {
	tail  []byte
	start int64
}

func (t *tailReader) ReadAt(p []byte, off int64) (int, error) {
	if off < t.start {
		return 0, errOutsideTail
	}
	i := off - t.start
	if i >= int64(len(t.tail)) {
		return 0, io.EOF
	}
	n := copy(p, t.tail[i:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func pemLabel(h []byte) (string, bool) {
	rest, ok := bytes.CutPrefix(bytes.TrimLeft(h, " \t\r\n"), []byte("-----BEGIN "))
	if !ok {
		return "", false
	}
	label, _, ok := bytes.Cut(rest, []byte("-----"))
	return string(label), ok && len(label) < 64
}

// isText reports whether the start of the data is UTF-8 without NULs,
// allowing a character cut off at the end.
func isText(h []byte) bool {
	if bytes.IndexByte(h, 0) >= 0 {
		return false
	}
	for range utf8.UTFMax {
		if utf8.Valid(h) {
			return true
		}
		if len(h) < sniffLen {
			return false
		}
		h = h[:len(h)-1]
	}
	return false
}
