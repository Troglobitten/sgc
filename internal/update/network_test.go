package update

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Troglobitten/sgc"
	"github.com/Troglobitten/sgc/internal/release"
)

// TestAgainstRealGitHub downloads the newest published SGC release from
// GitHub and verifies it with the built-in release key, exactly the way an
// installed SGC would.
//
// It needs the internet and a published release, so it only runs when asked:
//
//	SGC_NETWORK_TESTS=1 go test ./internal/update -run RealGitHub -v
//
// Run it after publishing a release. It proves the parts the offline tests
// cannot: that GitHub's answer is understood, that its redirect to the
// download servers is followed, and that what CI signed verifies here.
func TestAgainstRealGitHub(t *testing.T) {
	if os.Getenv("SGC_NETWORK_TESTS") != "1" {
		t.Skip("set SGC_NETWORK_TESTS=1 to run tests that need the internet")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	source := GitHubSource("Troglobitten/sgc", "sgc-test")
	latest, err := source.Latest(ctx)
	if err != nil {
		t.Fatalf("ask GitHub for the newest release: %v", err)
	}
	t.Logf("newest release: %s, published %s", latest.Version, latest.PublishedAt.Format(time.DateOnly))
	if latest.Notes == "" {
		t.Error("the release has no notes; SGC would show an empty description before updating")
	}

	keys, err := release.ParsePublicKeys(sgc.ReleasePublicKeyPEM())
	if err != nil {
		t.Fatal(err)
	}
	checksums, err := source.File(ctx, latest.Version, release.ChecksumsFile, maxChecksumsSize)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := source.File(ctx, latest.Version, release.SignatureFile, maxSignatureSize)
	if err != nil {
		t.Fatal(err)
	}
	if err := release.VerifyChecksums(checksums, signature, keys); err != nil {
		t.Fatalf("the published checksum list does not verify: %v", err)
	}

	for _, arch := range []string{"amd64", "arm64"} {
		name := release.ArchiveName(latest.Version, arch)
		archive, err := source.File(ctx, latest.Version, name, maxArchiveSize)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := release.VerifyFile(checksums, name, archive); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		t.Logf("%s: %d bytes, verified", name, len(archive))
	}
}
