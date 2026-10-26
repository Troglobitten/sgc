package main

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/Troglobitten/sgc/internal/public"
)

// fail2ban's bans, for the page (docs/design.md §14). The helper asks
// fail2ban itself, over fail2ban's own socket, which needs no privilege
// beyond being root: listing and lifting a ban change no rule of SGC's (a
// ban is fail2ban's, in the table for the internet).

func publicSystem() *public.System {
	return &public.System{Paths: public.DefaultPaths(), Run: runProgram, Log: slog.New(slog.NewTextHandler(os.Stdout, nil))}
}

func publicBans() ([]public.Ban, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	return publicSystem().Bans(ctx)
}

func publicUnban(addr netip.Addr) error {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	return publicSystem().Unban(ctx, addr)
}
