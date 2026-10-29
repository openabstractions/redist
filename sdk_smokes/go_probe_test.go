package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileIdentityDirectoryRejectsStableFile(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "models")
	if err := os.WriteFile(file, []byte("stable ordinary file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := fileIdentity([]string{file}); err != nil {
		t.Fatalf("generic file identity changed: %v", err)
	}
	if err := fileIdentity([]string{file, "--directory"}); err == nil || !strings.Contains(err.Error(), "requires a directory") {
		t.Fatalf("directory identity did not refuse the stable file: %v", err)
	}
	if err := fileIdentity([]string{root, "--directory"}); err != nil {
		t.Fatalf("held directory identity refused: %v", err)
	}
}

func TestNativePayloadObservationUsesHeldCanonicalFiles(t *testing.T) {
	root := t.TempDir()
	payload := filepath.Join(root, "payload")
	if err := os.Mkdir(payload, 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte("inert native payload fixture")
	if err := os.WriteFile(filepath.Join(payload, "program.exe"), content, 0600); err != nil {
		t.Fatal(err)
	}
	pin := map[string]any{"id": "program.exe", "path": "program.exe", "bytes": len(content), "sha256": fmt.Sprintf("%x", sha256.Sum256(content))}
	request, output := filepath.Join(root, "request.json"), filepath.Join(root, "output.json")
	write := func(value any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(request, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(map[string]any{"schema": 1, "root": payload, "files": []any{pin}})
	if err := payloadObservation([]string{request, output}); err != nil {
		t.Fatal(err)
	}
	var actual struct {
		Root     string `json:"root"`
		Identity string `json:"root_identity"`
		Files    []struct {
			ID, Path, SHA256, Identity string
			Bytes                      int64
			Plain                      bool
			AncestorsPlain             bool `json:"ancestors_plain"`
		} `json:"files"`
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &actual); err != nil {
		t.Fatal(err)
	}
	if actual.Root != payload || actual.Identity == "" || len(actual.Files) != 1 || actual.Files[0].Path != filepath.Join(payload, "program.exe") || actual.Files[0].Identity == "" || !actual.Files[0].Plain || !actual.Files[0].AncestorsPlain || actual.Files[0].SHA256 != pin["sha256"] {
		t.Fatalf("canonical observation differs: %s", raw)
	}
	if err = payloadObservation([]string{request, output}); err == nil {
		t.Fatal("existing output was replaced")
	}
}

func TestNativePayloadObservationRefusesChangedForeignAndAmbiguousMembers(t *testing.T) {
	for _, fault := range []string{"bytes", "hash", "missing", "parent", "absolute", "drive-relative", "rooted", "duplicate", "case-collision", "unknown-field"} {
		t.Run(fault, func(t *testing.T) {
			root := t.TempDir()
			payload := filepath.Join(root, "payload")
			if err := os.Mkdir(payload, 0700); err != nil {
				t.Fatal(err)
			}
			content := []byte("source-bound fixture")
			if err := os.WriteFile(filepath.Join(payload, "program.exe"), content, 0600); err != nil {
				t.Fatal(err)
			}
			pin := map[string]any{"id": "program.exe", "path": "program.exe", "bytes": len(content), "sha256": fmt.Sprintf("%x", sha256.Sum256(content))}
			files := []any{pin}
			switch fault {
			case "bytes":
				pin["bytes"] = len(content) + 1
			case "hash":
				pin["sha256"] = fmt.Sprintf("%x", sha256.Sum256([]byte("edited")))
			case "missing":
				pin["id"] = "missing.exe"
				pin["path"] = "missing.exe"
			case "parent":
				pin["id"] = "../program.exe"
				pin["path"] = "../program.exe"
			case "absolute":
				pin["id"] = filepath.Join(root, "outside.exe")
				pin["path"] = pin["id"]
			case "drive-relative":
				pin["id"] = "D:outside.exe"
				pin["path"] = pin["id"]
			case "rooted":
				pin["id"] = "/outside.exe"
				pin["path"] = pin["id"]
			case "duplicate":
				files = append(files, pin)
			case "case-collision":
				other := map[string]any{}
				for k, v := range pin {
					other[k] = v
				}
				other["id"] = "PROGRAM.EXE"
				other["path"] = "PROGRAM.EXE"
				files = append(files, other)
			case "unknown-field":
				pin["accepted"] = true
			}
			request, output := filepath.Join(root, "request.json"), filepath.Join(root, "output.json")
			raw, err := json.Marshal(map[string]any{"schema": 1, "root": payload, "files": files})
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(request, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err = payloadObservation([]string{request, output}); err == nil {
				t.Fatal("invalid original payload request passed")
			}
			if _, err = os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("failed payload observation published output")
			}
		})
	}
}
