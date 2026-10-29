// Windows installed-SDK smoke: native selection and one read-only config call.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	requireDirectory := len(args) == 2 && args[1] == "--directory"
	if (len(args) != 1 && !requireDirectory) || !filepath.IsAbs(args[0]) {
		return fmt.Errorf("usage: go_probe --file-identity ABSOLUTE_PATH [--directory]")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	h, err := fileid.Open(ctx, fileid.Self, args[0], fileid.Options{Links: fileid.RefuseLinks})
	if err != nil {
		return err
	}
	key := h.FileID().Key()
	if requireDirectory {
		info, err := h.File().Stat()
		if err != nil {
			return errors.Join(err, h.Close())
		}
		if !info.IsDir() {
			return errors.Join(errors.New("native file identity requires a directory"), h.Close())
		}
	}
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

// payloadObservation reuses the canonical held file owner for a bounded native
// archive inventory. Request pins are expectations; the parent rederives them
// from the authenticated producer and never trusts an installed marker.
func payloadObservation(args []string) (result error) {
	if len(args) != 2 || !filepath.IsAbs(args[0]) || !filepath.IsAbs(args[1]) {
		return fmt.Errorf("usage: go_probe --payload-observation REQUEST OUTPUT")
	}
	type member struct {
		ID     string `json:"id"`
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	}
	var request struct {
		Schema int      `json:"schema"`
		Root   string   `json:"root"`
		Files  []member `json:"files"`
	}
	input, err := os.Open(args[0])
	if err != nil {
		return err
	}
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128<<20 {
		return errors.Join(err, input.Close(), fmt.Errorf("bounded plain native payload request required"))
	}
	decoder := json.NewDecoder(io.LimitReader(input, (128<<20)+1))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&request)
	if err == nil && decoder.Decode(new(any)) != io.EOF {
		err = fmt.Errorf("one payload request required")
	}
	err = errors.Join(err, input.Close())
	if err != nil {
		return err
	}
	if request.Schema != 1 || !filepath.IsAbs(request.Root) || filepath.Clean(request.Root) != request.Root || len(request.Files) == 0 || len(request.Files) > 131073 {
		return fmt.Errorf("bounded absolute native payload inventory required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	root, err := fileid.Open(ctx, fileid.Self, request.Root, fileid.Options{Links: fileid.RefuseLinks})
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	type observed struct {
		member
		Identity       string `json:"identity"`
		Plain          bool   `json:"plain"`
		AncestorsPlain bool   `json:"ancestors_plain"`
	}
	rows := make([]observed, 0, len(request.Files))
	seen := make(map[string]bool, len(request.Files))
	var total int64
	buffer := make([]byte, 1<<20)
	for _, pin := range request.Files {
		name := filepath.FromSlash(pin.Path)
		key := strings.ToLower(name)
		if pin.ID != pin.Path || !filepath.IsLocal(name) || filepath.ToSlash(filepath.Clean(name)) != pin.Path || seen[key] || pin.Bytes < 0 || pin.Bytes > 16<<30-total || len(pin.SHA256) != 64 {
			return fmt.Errorf("native payload member differs")
		}
		seen[key] = true
		total += pin.Bytes
		h, err := root.Beneath(name, fileid.Options{Links: fileid.RefuseLinks, Read: true})
		if err != nil {
			return err
		}
		info, err := h.File().Stat()
		if err == nil && (!info.Mode().IsRegular() || info.Size() != pin.Bytes) {
			err = fmt.Errorf("native payload is not the expected plain file")
		}
		digest := sha256.New()
		var count int64
		for err == nil {
			if err = ctx.Err(); err != nil {
				break
			}
			var n int
			n, err = h.File().Read(buffer)
			if n > 0 {
				count += int64(n)
				_, _ = digest.Write(buffer[:n])
			}
			if count > pin.Bytes {
				err = fmt.Errorf("native payload grew while reading")
				break
			}
			if err == io.EOF {
				err = nil
				break
			}
		}
		if err == nil && (count != pin.Bytes || fmt.Sprintf("%x", digest.Sum(nil)) != pin.SHA256) {
			err = fmt.Errorf("native payload bytes differ")
		}
		identity := h.FileID().Key()
		if identity == "" || len(identity) > 256 {
			err = errors.Join(err, fmt.Errorf("native payload identity absent"))
		}
		err = errors.Join(err, h.Close())
		if err != nil {
			return err
		}
		pin.Path = filepath.Join(request.Root, name)
		rows = append(rows, observed{member: pin, Identity: identity, Plain: true, AncestorsPlain: true})
	}
	current, err := fileid.Open(ctx, fileid.Self, request.Root, fileid.Options{Links: fileid.RefuseLinks})
	if err != nil {
		return err
	}
	same := current.FileID().Key() == root.FileID().Key()
	if err := current.Close(); err != nil {
		return err
	}
	if !same {
		return fmt.Errorf("native payload root changed")
	}
	output, err := os.OpenFile(args[1], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	err = json.NewEncoder(output).Encode(struct {
		Root         string     `json:"root"`
		RootIdentity string     `json:"root_identity"`
		Files        []observed `json:"files"`
	}{request.Root, root.FileID().Key(), rows})
	return errors.Join(err, output.Close())
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "--file-identity" {
		return fileIdentity(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "--payload-observation" {
		return payloadObservation(os.Args[2:])
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
