package content

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
	"testing/iotest"
	"time"
)

func makeTar(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: "dir/", Typeflag: tar.TypeDir, Mode: 0o755, ModTime: time.Unix(1700000000, 0)})
	for i := range n {
		data := bytes.Repeat([]byte("x"), i%10*100)
		tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("dir/f%d.txt", i), Size: int64(len(data)), Mode: 0o644, ModTime: time.Unix(1700000000, 0)})
		tw.Write(data)
	}
	tw.Close()
	return buf.Bytes()
}

// analyze writes in small pieces to exercise buffering.
func analyze(t *testing.T, data []byte) *Report {
	t.Helper()
	var src io.Reader = bytes.NewReader(data)
	if len(data) < 1<<16 {
		src = iotest.OneByteReader(src)
	}
	r, err := Analyze(src)
	if err != nil {
		t.Fatal(err)
	}
	if r.Size != int64(len(data)) {
		t.Errorf("size %d, want %d", r.Size, len(data))
	}
	return r
}

func TestTar(t *testing.T) {
	r := analyze(t, makeTar(t, 3))
	if r.Type != "tar" || r.EntryCount != 4 || !r.Entries[0].Dir || r.Entries[3].Size != 200 {
		t.Fatalf("%+v", r)
	}
}

func TestTarGz(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Name = "backup.tar"
	gz.Write(makeTar(t, 2))
	gz.Close()
	r := analyze(t, buf.Bytes())
	if r.Type != "tar.gz" || r.EntryCount != 3 || r.Uncompressed == 0 {
		t.Fatalf("%+v", r)
	}
}

func TestGzipText(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte("hello world\n"))
	gz.Close()
	r := analyze(t, buf.Bytes())
	if r.Type != "gzip" || r.Description != "gzip-compressed text" || r.Uncompressed != 12 {
		t.Fatalf("%+v", r)
	}
}

func TestZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("word/document.xml")
	w.Write([]byte("<doc/>"))
	big, _ := zw.CreateHeader(&zip.FileHeader{Name: "random.bin", Method: zip.Store})
	io.CopyN(big, rand.Reader, 3*zipTail) // the directory is still in the tail
	zw.Close()
	r := analyze(t, buf.Bytes())
	if r.Type != "zip" || r.EntryCount != 2 || r.Description != "Word document (a zip archive)" ||
		r.Entries[1].Size != 3*zipTail {
		t.Fatalf("%+v", r)
	}
}

func TestManyEntries(t *testing.T) {
	r := analyze(t, makeTar(t, MaxEntries+5))
	if r.EntryCount != MaxEntries+6 || len(r.Entries) != MaxEntries || len(r.Notes) != 1 {
		t.Fatalf("count %d listed %d notes %v", r.EntryCount, len(r.Entries), r.Notes)
	}
}

func TestDamagedTar(t *testing.T) {
	data := makeTar(t, 3)
	r := analyze(t, data[:700])
	if r.Type != "tar" || len(r.Notes) == 0 {
		t.Fatalf("%+v", r)
	}
}

func TestSimpleTypes(t *testing.T) {
	cases := map[string]string{
		"":                                     "empty",
		"hello\nworld":                         "text",
		"%PDF-1.7\n":                           "pdf",
		"age-encryption.org/v1\n-> X25519 a":   "age",
		"-----BEGIN RSA PRIVATE KEY-----\nMII": "pem",
		"\x00\x01\x02\x03":                     "binary",
		"7z\xbc\xaf\x27\x1c\x00\x04":           "7z",
	}
	for in, want := range cases {
		if r := analyze(t, []byte(in)); r.Type != want {
			t.Errorf("%q: got %s (%s), want %s", in, r.Type, r.Description, want)
		}
	}
	// A multi-byte character cut at the sniff limit is still text.
	text := append(bytes.Repeat([]byte("a"), sniffLen-1), "é and more"...)
	if r := analyze(t, text); r.Type != "text" {
		t.Errorf("cut text: %s", r.Type)
	}
}
