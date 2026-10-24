package iconpack

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestAgainstTheRealPack fetches the icon pack published by the Icons
// workflow, with the device's own code, and looks a few icons up in it. It
// needs the internet, so it runs only when asked:
//
//	SGC_NETWORK_TESTS=1 go test ./internal/iconpack -run RealPack -v
//
// Run it after the workflow changed, or when devices report that the pack
// is refused.
func TestAgainstTheRealPack(t *testing.T) {
	if os.Getenv("SGC_NETWORK_TESTS") == "" {
		t.Skip("set SGC_NETWORK_TESTS=1 to fetch the real icon pack")
	}
	s := New(Config{Dir: t.TempDir(), ManifestURL: DefaultManifestURL})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := s.Update(ctx); err != nil {
		t.Fatal(err)
	}
	st := s.Status()
	t.Logf("pack %s: %d icons, %.1f MB, built %s", st.Version, st.Count, float64(st.Size)/(1<<20), st.Built.Format(time.RFC3339))
	if st.Count < 1000 {
		t.Errorf("only %d icons", st.Count)
	}
	for _, name := range []string{"jellyfin", "nextcloud", "home-assistant", "adguard-home", "plex"} {
		if s.Lookup(name) == nil {
			t.Errorf("no icon for %s", name)
		}
	}
}
