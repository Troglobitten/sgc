package iconpack

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Built says what Build made.
type Built struct {
	Manifest Manifest
	Skipped  int
}

// Build makes a pack from a checkout of the collection at commit: every PNG
// in png/ drawn anew by redraw (services.Redraw, passed in by
// tools/iconpack), the names and aliases from metadata.json (and nothing
// else from it: it also names contributors), the LICENSE, and a NOTICE of
// what was changed. It writes the pack and its manifest into out. The
// checkout is read as data only.
func Build(source, commit, out string, now time.Time, redraw func([]byte) ([]byte, error)) (Built, error) {
	if !ValidCommit(commit) {
		return Built{}, errors.New("the commit is not a full commit id")
	}
	raw, err := os.ReadFile(filepath.Join(source, "metadata.json"))
	if err != nil {
		return Built{}, err
	}
	var meta map[string]struct {
		Aliases []string `json:"aliases"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return Built{}, fmt.Errorf("metadata.json: %w", err)
	}
	license, err := os.ReadFile(filepath.Join(source, "LICENSE"))
	if err != nil {
		return Built{}, err
	}
	files, err := filepath.Glob(filepath.Join(source, "png", "*.png"))
	if err != nil {
		return Built{}, err
	}
	slices.Sort(files)

	index := Index{Source: Source, Commit: commit, Icons: map[string]Entry{}}
	type icon struct {
		name string
		png  []byte
	}
	var icons []icon
	skipped := 0
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".png")
		if !ValidName(name) {
			skipped++
			continue
		}
		data, err := readAtMost(file, 4<<20)
		if err != nil {
			skipped++
			continue
		}
		drawn, err := redraw(data)
		if err != nil || len(drawn) > maxIcon {
			skipped++
			continue
		}
		var aliases []string
		for _, alias := range meta[name].Aliases {
			if slug := Slug(alias); slug != "" && slug != name && !slices.Contains(aliases, slug) {
				aliases = append(aliases, slug)
			}
		}
		index.Icons[name] = Entry{Aliases: aliases}
		icons = append(icons, icon{name, drawn})
	}
	if len(icons) == 0 {
		return Built{}, errors.New("no icon could be drawn")
	}
	if len(icons) > maxEntries {
		return Built{}, fmt.Errorf("%d icons is more than a device takes (%d)", len(icons), maxEntries)
	}

	version := now.UTC().Format("20060102") + "-" + commit[:7]
	notice := fmt.Sprintf("Icons from %s (https://github.com/%s), commit %s,\n"+
		"under the Apache License 2.0 (LICENSE in this pack).\n\n"+
		"Changed by SGC: every icon was drawn anew at 64 by 64 pixels as PNG,\n"+
		"and only the icons' names and aliases were taken from metadata.json.\n", Source, Source, commit)
	indexJSON, err := json.Marshal(index)
	if err != nil {
		return Built{}, err
	}

	if err := os.MkdirAll(out, 0o755); err != nil {
		return Built{}, err
	}
	packName := "icons-" + version + ".tar"
	packFile, err := os.Create(filepath.Join(out, packName))
	if err != nil {
		return Built{}, err
	}
	hash := sha256.New()
	counter := &countingWriter{w: io.MultiWriter(packFile, hash)}
	tw := tar.NewWriter(counter)
	add := func(name string, data []byte) error {
		header := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: now.UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	err = errors.Join(add(IndexFile, indexJSON), add("LICENSE", license), add("NOTICE", []byte(notice)))
	for _, i := range icons {
		err = errors.Join(err, add("png/"+i.name+".png", i.png))
	}
	if err = errors.Join(err, tw.Close(), packFile.Close()); err != nil {
		return Built{}, err
	}

	manifest := Manifest{
		Version: version, Source: Source, Commit: commit, Built: now.UTC(), Count: len(icons),
		File: packName, Size: counter.n, SHA256: hex.EncodeToString(hash.Sum(nil)),
	}
	if err := manifest.check(); err != nil {
		return Built{}, fmt.Errorf("the pack would be refused by a device: %w", err)
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Built{}, err
	}
	if err := os.WriteFile(filepath.Join(out, ManifestFile), append(manifestJSON, '\n'), 0o644); err != nil {
		return Built{}, err
	}
	return Built{Manifest: manifest, Skipped: skipped}, nil
}

func readAtMost(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var b bytes.Buffer
	if n, err := io.Copy(&b, io.LimitReader(f, limit+1)); err != nil || n > limit {
		return nil, errors.New("too large")
	}
	return b.Bytes(), nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
