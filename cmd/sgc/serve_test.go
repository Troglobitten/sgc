package main

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer lets the test read output while serve is still writing to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestServeRunsUntilAskedToStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var out syncBuffer
	done := make(chan int, 1)

	go func() { done <- serve(ctx, &out) }()

	// It must keep running while nobody has asked it to stop.
	select {
	case code := <-done:
		t.Fatalf("serve returned early with exit code %d", code)
	case <-time.After(50 * time.Millisecond):
	}

	cancel()

	select {
	case code := <-done:
		if code != exitOK {
			t.Errorf("exit code = %d, want %d", code, exitOK)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not stop after being asked to")
	}

	for _, want := range []string{"started", "stopping"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output %q does not mention %q", out.String(), want)
		}
	}
}
