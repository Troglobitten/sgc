package services

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"

	"github.com/Troglobitten/sgc/internal/proxy"
)

const (
	iconSize     = 64
	maxIconBytes = 1 << 20
	maxPageBytes = 512 << 10
	// A service whose icon could not be found is asked again after a day.
	iconRetry = 24 * time.Hour
	// CatalogueURL is the public dashboard-icons catalogue, by name
	// (docs/design.md §10).
	CatalogueURL = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/%s.png"
)

// IconFetcher fetches icons: from the services themselves, and from the
// public catalogue.
type IconFetcher struct {
	// Catalogue fetches from the internet; nil means the catalogue is not used.
	Catalogue *http.Client
	// CatalogueURL is a format with one %s for the name.
	CatalogueURL string

	mu        sync.Mutex
	queue     chan int64
	attempted map[int64]time.Time
}

// NewIconFetcher returns a fetcher with ordinary clients.
func NewIconFetcher() *IconFetcher {
	return &IconFetcher{
		Catalogue:    &http.Client{Timeout: 10 * time.Second},
		CatalogueURL: CatalogueURL,
	}
}

func (f *IconFetcher) init() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.queue == nil {
		f.queue = make(chan int64, 64)
		f.attempted = map[int64]time.Time{}
	}
}

// lanClient fetches from one service: it does not check the device's
// certificate (home devices mostly have a self-signed one; an icon is all
// that is taken), and follows redirects only on the same device.
func lanClient(host string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // see above
			Proxy:           nil,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || req.URL.Host != host {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func (c *Catalog) fetchIconSoon(id int64) {
	if c.cfg.Icons == nil {
		return
	}
	c.cfg.Icons.init()
	c.cfg.Icons.mu.Lock()
	delete(c.cfg.Icons.attempted, id)
	c.cfg.Icons.mu.Unlock()
	select {
	case c.cfg.Icons.queue <- id:
	default: // the loop finds it at its next round anyway
	}
}

// iconLoop fetches the icons of services that have none: soon after one is
// added, and otherwise every ten minutes for those not tried for a day.
func (c *Catalog) iconLoop(ctx context.Context) {
	if c.cfg.Icons == nil {
		return
	}
	f := c.cfg.Icons
	f.init()
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	round := func() {
		all, err := c.List(ctx)
		if err != nil {
			return
		}
		for _, s := range all {
			f.mu.Lock()
			last, tried := f.attempted[s.ID]
			f.mu.Unlock()
			if s.HasIcon || (tried && c.cfg.Now().Sub(last) < iconRetry) || ctx.Err() != nil {
				continue
			}
			c.FetchIcon(ctx, s.ID)
		}
	}
	round()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			round()
		case id := <-f.queue:
			c.FetchIcon(ctx, id)
		}
	}
}

// FetchIcon looks for a service's icon and keeps it. Not finding one is not
// an error: the page then draws an initial.
func (c *Catalog) FetchIcon(ctx context.Context, id int64) {
	f := c.cfg.Icons
	if f == nil {
		return
	}
	f.init()
	f.mu.Lock()
	f.attempted[id] = c.cfg.Now()
	f.mu.Unlock()
	s, err := c.Get(ctx, id)
	if err != nil {
		return
	}
	icon, source := f.find(ctx, s, c.catalogueOn(ctx))
	if icon == nil {
		return
	}
	if _, err := c.cfg.DB.ExecContext(context.WithoutCancel(ctx), `INSERT INTO service_icon (service_id, png, source, fetched_at)
		VALUES (?, ?, ?, ?) ON CONFLICT (service_id) DO UPDATE SET png = excluded.png, source = excluded.source,
		fetched_at = excluded.fetched_at`, id, icon, source, c.cfg.Now().Unix()); err != nil {
		c.cfg.Log.Error("keep an icon", "service", s.Name, "error", err)
	}
}

// Icon returns a service's icon (always a PNG SGC drew), nil if it has none.
func (c *Catalog) Icon(ctx context.Context, id int64) ([]byte, error) {
	var data []byte
	err := c.cfg.DB.QueryRowContext(ctx, "SELECT png FROM service_icon WHERE service_id = ?", id).Scan(&data)
	if err != nil {
		return nil, nil
	}
	return data, nil
}

func (f *IconFetcher) find(ctx context.Context, s Service, catalogue bool) ([]byte, string) {
	if s.Kind == proxy.KindHTTP {
		base := &url.URL{Scheme: s.Scheme, Host: s.UpstreamIP + ":" + strconv.Itoa(s.UpstreamPort), Path: "/"}
		client := lanClient(base.Host)
		if page, err := get(ctx, client, base.String(), maxPageBytes); err == nil {
			for _, href := range iconLinks(page) {
				target, err := base.Parse(href)
				if err != nil || target.Host != base.Host || (target.Scheme != "http" && target.Scheme != "https") {
					continue
				}
				if icon, err := f.fetchImage(ctx, client, target.String()); err == nil {
					return icon, "page"
				}
			}
		}
		if icon, err := f.fetchImage(ctx, client, base.JoinPath("favicon.ico").String()); err == nil {
			return icon, "favicon"
		}
	}
	if catalogue && f.Catalogue != nil {
		for _, name := range catalogueNames(s) {
			if icon, err := f.fetchImage(ctx, f.Catalogue, fmt.Sprintf(f.CatalogueURL, url.PathEscape(name))); err == nil {
				return icon, "catalogue"
			}
		}
	}
	return nil, ""
}

// catalogueNames are the names to look a service up by: its own, and its
// title written as the catalogue writes names ("Home Assistant" is
// home-assistant).
func catalogueNames(s Service) []string {
	names := []string{s.Name}
	if s.Title != "" {
		var b strings.Builder
		for _, r := range strings.ToLower(s.Title) {
			switch {
			case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
				b.WriteRune(r)
			case r == ' ' || r == '-' || r == '_' || r == '.':
				if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
					b.WriteByte('-')
				}
			}
		}
		if slug := strings.Trim(b.String(), "-"); slug != "" && slug != s.Name {
			names = append(names, slug)
		}
	}
	return names
}

func get(ctx context.Context, client *http.Client, target string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SGC (icon)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("too large")
	}
	return data, nil
}

func (f *IconFetcher) fetchImage(ctx context.Context, client *http.Client, target string) ([]byte, error) {
	data, err := get(ctx, client, target, maxIconBytes)
	if err != nil {
		return nil, err
	}
	return Redraw(data)
}

// iconLinks returns the icons a page names, the most promising first: a
// touch icon (large, PNG), then icons with sizes, then any. SVG is never
// taken (see Redraw).
func iconLinks(page []byte) []string {
	type candidate struct {
		href  string
		score int
	}
	var found []candidate
	tokens := html.NewTokenizer(bytes.NewReader(page))
	for {
		kind := tokens.Next()
		if kind == html.ErrorToken {
			break
		}
		if kind != html.StartTagToken && kind != html.SelfClosingTagToken {
			continue
		}
		name, hasAttr := tokens.TagName()
		if string(name) == "body" {
			break
		}
		if string(name) != "link" || !hasAttr {
			continue
		}
		var rel, href, typ, sizes string
		for {
			key, value, more := tokens.TagAttr()
			switch string(key) {
			case "rel":
				rel = strings.ToLower(string(value))
			case "href":
				href = string(value)
			case "type":
				typ = strings.ToLower(string(value))
			case "sizes":
				sizes = strings.ToLower(string(value))
			}
			if !more {
				break
			}
		}
		if href == "" || !strings.Contains(rel, "icon") || strings.Contains(rel, "mask-icon") ||
			typ == "image/svg+xml" || strings.HasSuffix(strings.ToLower(href), ".svg") {
			continue
		}
		score := 1
		if strings.Contains(rel, "apple-touch-icon") {
			score = 3
		} else if sizes != "" && sizes != "any" {
			score = 2
		}
		found = append(found, candidate{href, score})
	}
	var out []string
	for score := 3; score >= 1; score-- {
		for _, c := range found {
			if c.score == score {
				out = append(out, c.href)
			}
		}
	}
	return out
}

// Redraw decodes an icon (PNG, JPEG, GIF or ICO) and draws it anew as a PNG
// of 64 by 64 pixels. Whatever a service served, only pixels reach SGC's
// page: no SVG (which can carry scripts), no other data in the file.
func Redraw(data []byte) ([]byte, error) {
	var src image.Image
	var err error
	switch {
	case bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		src, err = png.Decode(bytes.NewReader(data))
	case bytes.HasPrefix(data, []byte{0xff, 0xd8, 0xff}):
		src, err = jpeg.Decode(bytes.NewReader(data))
	case bytes.HasPrefix(data, []byte("GIF8")):
		src, err = gif.Decode(bytes.NewReader(data))
	case bytes.HasPrefix(data, []byte{0, 0, 1, 0}):
		src, err = decodeICO(data)
	default:
		return nil, errors.New("not an image SGC reads")
	}
	if err != nil {
		return nil, err
	}
	bounds := src.Bounds()
	if bounds.Dx() < 8 || bounds.Dy() < 8 || bounds.Dx() > 4096 || bounds.Dy() > 4096 {
		return nil, errors.New("an icon of an odd size")
	}
	dst := image.NewNRGBA(image.Rect(0, 0, iconSize, iconSize))
	// Fit it into the square, keeping its proportions.
	scale := float64(iconSize) / float64(max(bounds.Dx(), bounds.Dy()))
	w, h := int(float64(bounds.Dx())*scale+0.5), int(float64(bounds.Dy())*scale+0.5)
	offX, offY := (iconSize-w)/2, (iconSize-h)/2
	draw.Draw(dst, dst.Bounds(), image.Transparent, image.Point{}, draw.Src)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			dst.Set(offX+x, offY+y, average(src, bounds, x, y, w, h))
		}
	}
	var out bytes.Buffer
	if err := png.Encode(&out, dst); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// average is the colour of the part of src that pixel (x, y) of a w×h
// picture covers.
func average(src image.Image, b image.Rectangle, x, y, w, h int) color.NRGBA {
	x0, x1 := b.Min.X+x*b.Dx()/w, b.Min.X+(x+1)*b.Dx()/w
	y0, y1 := b.Min.Y+y*b.Dy()/h, b.Min.Y+(y+1)*b.Dy()/h
	if x1 <= x0 {
		x1 = x0 + 1
	}
	if y1 <= y0 {
		y1 = y0 + 1
	}
	var r, g, bl, a, n uint64
	for yy := y0; yy < y1; yy++ {
		for xx := x0; xx < x1; xx++ {
			cr, cg, cb, ca := src.At(xx, yy).RGBA()
			r, g, bl, a, n = r+uint64(cr), g+uint64(cg), bl+uint64(cb), a+uint64(ca), n+1
		}
	}
	if a == 0 {
		return color.NRGBA{}
	}
	// The sums are of colours premultiplied by alpha; undo that.
	return color.NRGBA{R: uint8(r * 255 / a), G: uint8(g * 255 / a), B: uint8(bl * 255 / a), A: uint8(a / n >> 8)}
}

// decodeICO reads a .ico file: it takes the largest picture in it, which is
// either a PNG or a bitmap of 24 or 32 bits per pixel.
func decodeICO(data []byte) (image.Image, error) {
	if len(data) < 6 {
		return nil, errors.New("a broken icon file")
	}
	count := int(binary.LittleEndian.Uint16(data[4:]))
	if count == 0 || len(data) < 6+16*count {
		return nil, errors.New("a broken icon file")
	}
	best, bestSize := -1, -1
	for i := range count {
		entry := data[6+16*i:]
		w, h := int(entry[0]), int(entry[1])
		if w == 0 {
			w = 256
		}
		if h == 0 {
			h = 256
		}
		if w*h > bestSize {
			best, bestSize = i, w*h
		}
	}
	entry := data[6+16*best:]
	size := int(binary.LittleEndian.Uint32(entry[8:]))
	offset := int(binary.LittleEndian.Uint32(entry[12:]))
	if offset < 0 || size <= 0 || offset+size > len(data) {
		return nil, errors.New("a broken icon file")
	}
	picture := data[offset : offset+size]
	if bytes.HasPrefix(picture, []byte("\x89PNG\r\n\x1a\n")) {
		return png.Decode(bytes.NewReader(picture))
	}
	return decodeDIB(picture)
}

// decodeDIB reads the bitmap inside an icon: a BITMAPINFOHEADER, then the
// rows bottom to top (twice the picture's height is given, because a mask
// follows the colours).
func decodeDIB(b []byte) (image.Image, error) {
	if len(b) < 40 || binary.LittleEndian.Uint32(b) < 40 {
		return nil, errors.New("not a bitmap SGC reads")
	}
	headerSize := int(binary.LittleEndian.Uint32(b))
	width := int(int32(binary.LittleEndian.Uint32(b[4:])))
	height := int(int32(binary.LittleEndian.Uint32(b[8:]))) / 2
	bits := int(binary.LittleEndian.Uint16(b[14:]))
	compression := binary.LittleEndian.Uint32(b[16:])
	if width <= 0 || height <= 0 || width > 512 || height > 512 || compression != 0 || (bits != 32 && bits != 24) {
		return nil, errors.New("not a bitmap SGC reads")
	}
	bytesPerPixel := bits / 8
	stride := (width*bytesPerPixel + 3) &^ 3
	if headerSize+stride*height > len(b) {
		return nil, errors.New("a broken bitmap")
	}
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	for y := range height {
		row := b[headerSize+(height-1-y)*stride:]
		for x := range width {
			p := row[x*bytesPerPixel:]
			alpha := uint8(255)
			if bytesPerPixel == 4 {
				alpha = p[3]
			}
			img.SetNRGBA(x, y, color.NRGBA{R: p[2], G: p[1], B: p[0], A: alpha})
		}
	}
	return img, nil
}
