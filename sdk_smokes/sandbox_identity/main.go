//go:build windows

// Private Windows Sandbox readback adapter. It grants no runtime authority.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/openabstractions/abstraction-facade/go-core/bootstrap"
	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/fileid"
	"github.com/openabstractions/abstraction-identity/listen"
)

type inventoryProcess struct {
	PID     int    `json:"pid"`
	Started string `json:"started"`
}
type probeInput struct {
	Guest     string             `json:"guest_id"`
	Tools     string             `json:"tools"`
	Processes []inventoryProcess `json:"processes"`
}
type fileObservation struct {
	Path   string `json:"path"`
	Key    string `json:"file_key"`
	SHA256 string `json:"sha256"`
}
type processObservation struct {
	Role    string          `json:"role"`
	PID     int             `json:"pid"`
	Started string          `json:"started"`
	Image   fileObservation `json:"image"`
}
type probeResult struct {
	Schema    int                        `json:"schema"`
	Guest     string                     `json:"guest_id"`
	Complete  bool                       `json:"complete"`
	KeyScope  string                     `json:"key_scope"`
	Installed map[string]fileObservation `json:"installed"`
	Processes []processObservation       `json:"processes"`
}

func observeFile(ctx context.Context, path string) (fileObservation, fileid.Handle, error) {
	h, err := fileid.Open(ctx, fileid.Self, path, fileid.Options{Links: fileid.RefuseLinks, Read: true})
	if err != nil {
		return fileObservation{}, h, err
	}
	id := h.FileID()
	if id.IsZero() || id.IsDir() || id.Links() != 1 {
		return fileObservation{}, fileid.Handle{}, errors.Join(errors.New("image is not one held regular file"), h.Close())
	}
	digest := sha256.New()
	if _, err = io.Copy(digest, h.File()); err != nil {
		return fileObservation{}, fileid.Handle{}, errors.Join(err, h.Close())
	}
	return fileObservation{Path: id.Path(), Key: id.Key(), SHA256: hex.EncodeToString(digest.Sum(nil))}, h, nil
}

func capture(ctx context.Context, input probeInput) (result probeResult, err error) {
	// The installed user runtime and its supervisor must both be observed.
	// Extra inventory entries remain unproved and refuse complete coverage.
	if len(input.Guest) != 32 || !filepath.IsAbs(input.Tools) || len(input.Processes) != 2 {
		return result, errors.New("incomplete guest/runtime inventory")
	}
	if _, err := hex.DecodeString(input.Guest); err != nil {
		return result, err
	}
	selected, err := bootstrap.SelectInstalled(ctx)
	if err != nil || selected.EndpointFromEnvironment {
		return result, errors.New("no native installed runtime selection")
	}
	conn, err := listen.Dial(selected.Endpoint)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, conn.Close()) }()
	bound, err := identity.BindServerConn(conn, &identity.Options{SkipCodeSignature: true})
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, bound.Close()) }()
	peer, err := bound.Peer()
	if err != nil {
		return result, err
	}
	user, err := peer.User.AtLeast(identity.ProofBound)
	if err != nil {
		return result, err
	}
	account, err := user.Account()
	expected, expectedErr := selected.Server.Principal.Account()
	if err != nil || expectedErr != nil || account != expected {
		return result, errors.New("runtime principal differs")
	}
	process, err := peer.Process.AtLeast(identity.ProofKernel)
	if err != nil || process.Recycled || process.StartTime.IsZero() {
		return result, errors.New("runtime process unproved")
	}
	result = probeResult{Schema: 1, Guest: input.Guest, KeyScope: "windows-volume-file-id", Installed: map[string]fileObservation{}}
	for _, name := range []string{"openabstractions", "openabstractionsw"} {
		observed, held, e := observeFile(ctx, filepath.Join(input.Tools, name+".exe"))
		if e != nil {
			return probeResult{}, e
		}
		defer func() { err = errors.Join(err, held.Close()) }()
		result.Installed[name] = observed
	}
	roles := map[string]bool{}
	seen := map[int]bool{}
	var observations []*identity.SourceProcessObservation
	for _, candidate := range input.Processes {
		started, e := time.Parse(time.RFC3339Nano, candidate.Started)
		if e != nil || seen[candidate.PID] {
			return probeResult{}, errors.New("invalid or duplicate runtime generation")
		}
		seen[candidate.PID] = true
		observed, e := identity.OpenSourceProcessObservation(ctx, identity.Process{PID: candidate.PID, StartTime: started}, expected)
		if e != nil {
			return probeResult{}, e
		}
		defer func() { err = errors.Join(err, observed.Close()) }()
		observations = append(observations, observed)
		image, held, e := observeFile(ctx, observed.ImagePath)
		if e != nil {
			return probeResult{}, e
		}
		defer func() { err = errors.Join(err, held.Close()) }()
		role := ""
		for name, installed := range result.Installed {
			if installed.Key == image.Key && installed.SHA256 == image.SHA256 {
				if name == "openabstractions" {
					role = "user_runtime"
				} else {
					role = "supervisor"
				}
			}
		}
		if role == "" || roles[role] || (role == "user_runtime" &&
			(observed.Process.PID != process.PID || !observed.Process.StartTime.Equal(process.StartTime))) {
			return probeResult{}, errors.New("runtime role or installed image is unproved")
		}
		roles[role] = true
		result.Processes = append(result.Processes, processObservation{Role: role, PID: observed.Process.PID,
			Started: observed.Process.StartTime.UTC().Format(time.RFC3339Nano), Image: image})
	}
	if !roles["user_runtime"] || !roles["supervisor"] {
		return probeResult{}, errors.New("required runtime roles are incomplete")
	}
	for _, observation := range observations {
		if err = observation.Recheck(); err != nil {
			return probeResult{}, err
		}
		alive, e := observation.Alive()
		if e != nil || !alive {
			return probeResult{}, errors.New("observed runtime role exited during capture")
		}
	}
	if _, err = bound.Peer(); err != nil {
		return probeResult{}, err
	}
	alive, err := bound.Alive()
	if err != nil || !alive {
		return probeResult{}, errors.New("bound runtime exited during capture")
	}
	result.Complete = true
	return result, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: sandbox_identity_probe INPUT.json")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	var input probeInput
	if err == nil && len(raw) <= 65536 {
		err = json.Unmarshal(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf}), &input)
	} else if err == nil {
		err = errors.New("input exceeds bound")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := capture(ctx, input)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
