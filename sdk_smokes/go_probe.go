// Windows installed-SDK smoke: native selection and one read-only config call.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/openabstractions/abstraction-facade/go-core/bootstrap"
	"github.com/openabstractions/abstraction-facade/go/client"
)

func run() error {
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
