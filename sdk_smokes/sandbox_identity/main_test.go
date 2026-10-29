//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/openabstractions/abstraction-identity/fileid"
)

func TestSandboxFileObservationUsesRealHeldNativeKeyAndBytes(t *testing.T) {
	root := t.TempDir()
	var observations []fileObservation
	for _, name := range []string{"one.exe", "two.exe"} {
		path := filepath.Join(root, name)
		body := []byte("inert native identity fixture")
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		observed, held, err := observeFile(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		again, err := fileid.Open(context.Background(), fileid.Self, path, fileid.Options{Links: fileid.RefuseLinks})
		if err != nil {
			t.Fatal(err)
		}
		if observed.Key == "" || observed.Key != again.FileID().Key() {
			t.Fatal("native volume/file key changed")
		}
		if err := again.Close(); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		if observed.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatal("hash did not name held bytes")
		}
		observations = append(observations, observed)
	}
	if observations[0].Key == observations[1].Key {
		t.Fatal("equal bytes collapsed distinct native files")
	}
}
