// Command sgc-standin plays the parts of the outside world that the
// whole-machine test must not touch for real. For now that is Zone.eu's API:
// one account with one domain, which accepts one username and API key.
//
// It is built by the test-release scripts, copied to the test machine and
// started there by cases.sh. It is not part of any release.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Troglobitten/sgc/internal/zone/zonetest"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9100", "address to listen on")
	username := flag.String("username", "", "the ZoneID username the account accepts")
	apiKey := flag.String("api-key", "", "the API key the account accepts")
	domain := flag.String("domain", "domain.tld", "the domain whose DNS zone is in the account")
	flag.Parse()
	if *username == "" || *apiKey == "" {
		fmt.Fprintln(os.Stderr, "sgc-standin: --username and --api-key are needed")
		os.Exit(2)
	}
	server := &http.Server{
		Addr:              *listen,
		Handler:           zonetest.New(*username, *apiKey, *domain),
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Printf("standing in for Zone.eu on %s, with the zone %s\n", *listen, *domain)
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "sgc-standin:", err)
		os.Exit(1)
	}
}
