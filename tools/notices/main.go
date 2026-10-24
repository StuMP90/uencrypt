// Command notices writes THIRD-PARTY-NOTICES.txt: the licence text of
// every Go module (and the Go standard library) compiled into a binary,
// plus the front-end packages bundled into the GUI.
//
//	go run ./tools/notices -o notices.txt ./cmd/uencrypt
//	go run ./tools/notices -goos windows -npm gui/frontend -o notices.txt ./gui
//
// The package list depends on the target system and build tags, so pass
// the same ones as the build it ships with.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// npmBundled are the front-end packages that end up in the GUI bundle
// (everything else under node_modules is build tooling).
var npmBundled = []string{"react", "react-dom", "scheduler"}

func main() {
	out := flag.String("o", "", "output file (default stdout)")
	tags := flag.String("tags", "", "build tags, as for go build")
	goos := flag.String("goos", "", "target GOOS (default this system)")
	goarch := flag.String("goarch", "", "target GOARCH (default this system)")
	npm := flag.String("npm", "", "front-end directory whose bundled packages are included")
	flag.Parse()
	if flag.NArg() == 0 {
		log.Fatal("usage: notices [-o file] [-tags tags] [-npm dir] packages...")
	}

	type entry struct{ name, licence string }
	var entries []entry

	args := []string{"list", "-deps", "-f", "{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}{{end}}"}
	if *tags != "" {
		args = append(args, "-tags", *tags)
	}
	list := exec.Command("go", append(args, flag.Args()...)...)
	list.Env = os.Environ()
	if *goos != "" {
		list.Env = append(list.Env, "GOOS="+*goos)
	}
	if *goarch != "" {
		list.Env = append(list.Env, "GOARCH="+*goarch)
	}
	list.Stderr = os.Stderr
	listing, err := list.Output()
	if err != nil {
		log.Fatalf("go list: %v", err)
	}
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(listing))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) != 3 || seen[f[0]] {
			continue
		}
		seen[f[0]] = true
		text, err := licenceIn(f[2])
		if err != nil {
			log.Fatalf("%s: %v", f[0], err)
		}
		entries = append(entries, entry{f[0] + " " + f[1], text})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	goroot, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		log.Fatalf("go env: %v", err)
	}
	text, err := licenceIn(strings.TrimSpace(string(goroot)))
	if err != nil {
		log.Fatalf("Go: %v", err)
	}
	entries = append([]entry{{"The Go programming language (" + runtime.Version() + " runtime and standard library)", text}}, entries...)

	if *npm != "" {
		for _, name := range npmBundled {
			dir := filepath.Join(*npm, "node_modules", name)
			text, err := licenceIn(dir)
			if err != nil {
				log.Fatalf("npm %s: %v", name, err)
			}
			entries = append(entries, entry{name + " " + npmVersion(dir) + " (npm)", text})
		}
	}

	var b strings.Builder
	b.WriteString("uEncrypt includes the following third-party software.\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "\n%s\n%s\n\n%s\n", strings.Repeat("=", 78), e.name, strings.TrimSpace(e.licence))
	}
	if *out == "" {
		os.Stdout.WriteString(b.String())
		return
	}
	if err := os.WriteFile(*out, []byte(b.String()), 0o644); err != nil {
		log.Fatal(err)
	}
}

// licenceIn returns the licence (and any NOTICE) files at the top of dir.
func licenceIn(dir string) (string, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var parts []string
	for _, f := range files {
		n := strings.ToUpper(f.Name())
		if f.IsDir() || !(strings.HasPrefix(n, "LICENSE") || strings.HasPrefix(n, "LICENCE") ||
			strings.HasPrefix(n, "COPYING") || strings.HasPrefix(n, "NOTICE") || n == "PATENTS") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			return "", err
		}
		parts = append(parts, strings.TrimSpace(string(data)))
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("no licence file in %s", dir)
	}
	return strings.Join(parts, "\n\n"), nil
}

func npmVersion(dir string) string {
	var pkg struct{ Version string }
	if data, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil {
		json.Unmarshal(data, &pkg)
	}
	return pkg.Version
}
