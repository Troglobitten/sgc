package iconpack

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const commit = "d3b9234dd56f3af5862f06741f0dce101193b3df"

var built = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func square(c color.Color) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, 32, 32))
	for y := range 32 {
		for x := range 32 {
			img.Set(x, y, c)
		}
	}
	var b bytes.Buffer
	png.Encode(&b, img)
	return b.Bytes()
}

// redraw stands in for services.Redraw: a PNG in, a PNG out.
func redraw(data []byte) ([]byte, error) {
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err = png.Encode(&b, img)
	return b.Bytes(), err
}

// upstream is a made-up checkout of the collection.
func upstream(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "png"), 0o755)
	meta := `{"jellyfin": {"aliases": ["Jelly Fin"], "update": {"author": {"name": "someone@example.com"}}},
	          "home-assistant": {"aliases": ["HA", "jellyfin"]}}`
	os.WriteFile(filepath.Join(dir, "metadata.json"), []byte(meta), 0o644)
	os.WriteFile(filepath.Join(dir, "LICENSE"), []byte("Apache License 2.0 (made-up copy for the test)"), 0o644)
	os.WriteFile(filepath.Join(dir, "png", "jellyfin.png"), square(color.RGBA{0, 0, 255, 255}), 0o644)
	os.WriteFile(filepath.Join(dir, "png", "home-assistant.png"), square(color.RGBA{0, 255, 0, 255}), 0o644)
	os.WriteFile(filepath.Join(dir, "png", "Not A Name.png"), square(color.Black), 0o644)
	os.WriteFile(filepath.Join(dir, "png", "broken.png"), []byte("not an image"), 0o644)
	return dir
}

// published serves a folder as the place the pack is published, counting
// the downloads of packs.
type published struct {
	dir       string
	server    *httptest.Server
	downloads atomic.Int32
}

func publish(t *testing.T, dir string) *published {
	p := &published{dir: dir}
	files := http.FileServer(http.Dir(dir))
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".tar") {
			p.downloads.Add(1)
		}
		files.ServeHTTP(w, r)
	}))
	t.Cleanup(p.server.Close)
	return p
}

func device(t *testing.T, manifestURL, dir string, installed *atomic.Int32) *Service {
	return New(Config{Dir: dir, ManifestURL: manifestURL, Installed: func() {
		if installed != nil {
			installed.Add(1)
		}
	}})
}

func TestAPackFromTheCollection(t *testing.T) {
	out := t.TempDir()
	result, err := Build(upstream(t), commit, out, built, redraw)
	if err != nil {
		t.Fatal(err)
	}
	m := result.Manifest
	if m.Count != 2 || result.Skipped != 2 || m.Version != "20261024-d3b9234" {
		t.Fatalf("built %+v, skipped %d", m, result.Skipped)
	}
	packed, _ := os.ReadFile(filepath.Join(out, m.File))
	if bytes.Contains(packed, []byte("someone@example.com")) {
		t.Error("the pack carries the collection's contributors")
	}
	if !bytes.Contains(packed, []byte("drawn anew")) || !bytes.Contains(packed, []byte("Apache License")) {
		t.Error("the pack lacks the licence or the notice of the change")
	}

	p := publish(t, out)
	dir := t.TempDir()
	var installed atomic.Int32
	s := device(t, p.server.URL+"/"+ManifestFile, dir, &installed)
	if s.Lookup("jellyfin") != nil || s.Status().Installed {
		t.Fatal("a pack before one was fetched")
	}
	if err := s.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := s.Status()
	if !st.Installed || st.Count != 2 || st.Version != m.Version || st.CheckedAt == nil || st.Problem != "" || installed.Load() != 1 {
		t.Fatalf("after the update: %+v, installed called %d times", st, installed.Load())
	}
	for name, want := range map[string]string{"jellyfin": "jellyfin", "jelly-fin": "jellyfin", "ha": "home-assistant", "home-assistant": "home-assistant"} {
		got := s.Lookup("not-there", name)
		wantData, _ := os.ReadFile(filepath.Join(dir, m.Version, "png", want+".png"))
		if got == nil || !bytes.Equal(got, wantData) {
			t.Errorf("Lookup(%q) did not find %s", name, want)
		}
	}
	// An alias never takes the place of an icon of that name.
	if got := s.Lookup("jellyfin"); !bytes.Equal(got, mustRead(t, filepath.Join(dir, m.Version, "png", "jellyfin.png"))) {
		t.Error("an alias took the place of the icon of the same name")
	}
	if s.Lookup("nothing-by-this-name") != nil {
		t.Error("an icon for a name the pack does not have")
	}

	// Nothing new: nothing downloaded.
	if err := s.Update(context.Background()); err != nil || p.downloads.Load() != 1 || installed.Load() != 1 {
		t.Errorf("a second look: %v, %d downloads, installed %d times", err, p.downloads.Load(), installed.Load())
	}
	// After a restart the pack is there at once.
	if again := device(t, p.server.URL+"/"+ManifestFile, dir, nil); again.Lookup("ha") == nil || !again.Status().Installed {
		t.Error("the pack was not there after a restart")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// publishNew puts a pack (made by the test, possibly wrong) and its manifest
// in the published folder, as a newer version.
func publishNew(t *testing.T, dir string, files map[string][]byte, links []string, tamper bool) Manifest {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	count := 0
	index := Index{Source: Source, Commit: strings.Repeat("e", 40), Icons: map[string]Entry{}}
	for name := range files {
		if icon, ok := strings.CutPrefix(name, "png/"); ok && strings.HasSuffix(icon, ".png") {
			index.Icons[strings.TrimSuffix(icon, ".png")] = Entry{}
			count++
		}
	}
	indexJSON, _ := json.Marshal(index)
	all := map[string][]byte{IndexFile: indexJSON}
	for k, v := range files {
		all[k] = v
	}
	for name, data := range all {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg})
		tw.Write(data)
	}
	for _, link := range links {
		tw.WriteHeader(&tar.Header{Name: link, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	}
	tw.Close()
	data := b.Bytes()
	sum := sha256.Sum256(data)
	m := Manifest{Version: "20261031-eeeeeee", Source: Source, Commit: index.Commit, Built: built, Count: count,
		File: "icons-20261031-eeeeeee.tar", Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
	if tamper {
		data[len(data)/2] ^= 0xff
	}
	os.WriteFile(filepath.Join(dir, m.File), data, 0o644)
	manifestJSON, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(dir, ManifestFile), manifestJSON, 0o644)
	return m
}

func TestWhatIsRefused(t *testing.T) {
	good := square(color.White)
	for name, c := range map[string]struct {
		files  map[string][]byte
		links  []string
		tamper bool
		want   string
	}{
		"a pack that does not match its checksum": {files: map[string][]byte{"png/a.png": good}, tamper: true, want: "checksum"},
		"a file a pack does not have":             {files: map[string][]byte{"png/a.png": good, "run.sh": []byte("echo")}, want: "does not have"},
		"a way out of its folder":                 {files: map[string][]byte{"png/a.png": good, "../a.png": good}, want: "does not have"},
		"a link":                                  {files: map[string][]byte{"png/a.png": good}, links: []string{"png/b.png"}, want: "other than files"},
		"an icon that is not a PNG":               {files: map[string][]byte{"png/a.png": []byte("<svg onload=alert(1)>")}, want: "not a PNG"},
	} {
		t.Run(name, func(t *testing.T) {
			out := t.TempDir()
			if _, err := Build(upstream(t), commit, out, built, redraw); err != nil {
				t.Fatal(err)
			}
			p := publish(t, out)
			dir := t.TempDir()
			s := device(t, p.server.URL+"/"+ManifestFile, dir, nil)
			if err := s.Update(context.Background()); err != nil {
				t.Fatal(err)
			}
			before := s.Status().Version

			publishNew(t, out, c.files, c.links, c.tamper)
			err := s.Update(context.Background())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to say %q", err, c.want)
			}
			// The pack in use stays, and the problem is shown.
			if st := s.Status(); st.Version != before || s.Lookup("jellyfin") == nil || !strings.Contains(st.Problem, c.want) {
				t.Errorf("after the refusal: %+v", st)
			}
			if _, err := os.Stat(filepath.Join(dir, "20261031-eeeeeee")); err == nil {
				t.Error("the refused pack was left in place")
			}
			if _, err := os.Lstat(filepath.Join(dir, "20261031-eeeeeee.new", "png", "b.png")); err == nil {
				t.Error("a link from the refused pack was made")
			}
		})
	}
}

func TestAManifestThatIsNotAPacksIsRefused(t *testing.T) {
	for name, edit := range map[string]func(*Manifest){
		"another source":      func(m *Manifest) { m.Source = "someone/else" },
		"another file":        func(m *Manifest) { m.File = "../../etc/x.tar" },
		"a version that lies": func(m *Manifest) { m.Version = "20261024-0000000" },
		"too large":           func(m *Manifest) { m.Size = maxPack + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			out := t.TempDir()
			result, err := Build(upstream(t), commit, out, built, redraw)
			if err != nil {
				t.Fatal(err)
			}
			m := result.Manifest
			edit(&m)
			raw, _ := json.Marshal(m)
			os.WriteFile(filepath.Join(out, ManifestFile), raw, 0o644)
			p := publish(t, out)
			s := device(t, p.server.URL+"/"+ManifestFile, t.TempDir(), nil)
			if err := s.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "refused") || p.downloads.Load() != 0 {
				t.Errorf("err = %v, %d downloads", err, p.downloads.Load())
			}
		})
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{"Home Assistant": "home-assistant", "AdGuard Home": "adguard-home", "  --x_y.z ": "x-y-z", "Ünïcode": "ncode", "": ""} {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
}
