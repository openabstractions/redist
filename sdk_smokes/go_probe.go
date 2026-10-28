// Windows installed-SDK smoke: native selection and one read-only config call.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openabstractions/abstraction-facade/go-core/bootstrap"
	"github.com/openabstractions/abstraction-facade/go/client"
	"github.com/openabstractions/abstraction-identity/fileid"
)

// fileIdentity is a read-only adapter to the canonical file identity owner.
// It runs independently of installed-runtime discovery.
func fileIdentity(args []string) error {
	if len(args) != 1 || !filepath.IsAbs(args[0]) {
		return fmt.Errorf("usage: go_probe --file-identity ABSOLUTE_PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	h, err := fileid.Open(ctx, fileid.Self, args[0], fileid.Options{Links: fileid.RefuseLinks})
	if err != nil {
		return err
	}
	key := h.FileID().Key()
	if err := h.Close(); err != nil {
		return err
	}
	if key == "" || len(key) > 256 {
		return fmt.Errorf("file identity owner returned no bounded key")
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Schema int    `json:"schema"`
		Key    string `json:"key"`
	}{Schema: 1, Key: key})
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "--file-identity" {
		return fileIdentity(os.Args[2:])
	}
	if len(os.Args) != 3 || os.Getenv("ABSTRACTION_RUNTIME_ENDPOINT") != "" {
		return fmt.Errorf("usage: go_probe EXPECTED_SID EXPECTED_PROGRAM (no endpoint override)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	selected, err := bootstrap.SelectInstalled(ctx)
	if err != nil {
		return fmt.Errorf("installed selection: %w", err)
	}
	if selected.Server.Principal.Kind != "windows" || selected.Server.Principal.SID != os.Args[1] || !strings.EqualFold(selected.Server.Program, os.Args[2]) {
		return fmt.Errorf("installed selection did not name the expected Windows account and program")
	}
	editor, err := client.Discover().ResolveConfigEditor(ctx, client.Requirements{})
	if err != nil {
		var refusal *client.ResolutionError
		if errors.As(err, &refusal) && refusal.Status == client.RuntimeUnavailable {
			return fmt.Errorf("typed runtime_unavailable during default config discovery: %w", err)
		}
		return fmt.Errorf("default config discovery: %w", err)
	}
	snapshot, err := editor.ReadUserContext(ctx)
	if err != nil {
		return fmt.Errorf("config ReadUser: %w", err)
	}
	if snapshot.Revision == "" {
		return fmt.Errorf("config ReadUser returned no revision")
	}
	fmt.Println("PASS Go installed selection, default discovery and config ReadUser")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
