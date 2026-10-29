package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// nativeSDKFiles is the generated record-codec closure used by UI callbacks.
// AppModel state and MCP sessions run in the signed native host.
var nativeSDKFiles = []string{
	"abstraction-facade/javascript/js/abstraction/facade/appmodel/internal.mjs",
	"abstraction-facade/javascript/js/abstraction/facade/applications/index.mjs",
	"abstraction-facade/javascript/js/abstraction/facade/applications/internal.mjs",
	"abstraction-facade/javascript/js/abstraction/facade/registration/internal.mjs",
	"abstraction-facade/javascript/js/abstraction/facade/internal.mjs",
	"abstraction-download/javascript/js/abstraction/download/request/internal.mjs",
	"abstraction-rights/javascript/js/abstraction/rights/api/internal.mjs",
	"abstraction-resource/javascript/js/abstraction/resource/internal.mjs",
	"abstraction-logging/javascript/js/abstraction/logging/internal.mjs",
	"abstraction-inference/javascript/js/abstraction/inference/api/internal.mjs",
	"abstraction-job/javascript/js/abstraction/job/acceptance/internal.mjs",
}

func writeNativeResources(monitorDir string) error {
	root := filepath.Join(filepath.Dir(monitorDir), "openabstractions-flat")
	for _, name := range nativeSDKFiles {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return fmt.Errorf("native Panel SDK %s: %w", name, err)
		}
		target := filepath.Join(monitorDir, "static", "native-sdk", filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(target, body, 0644); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(monitorDir, "panel-application.json"), nativeManifest(), 0644)
}

func nativeManifest() []byte {
	return []byte(`{
  "version": "applications@3",
  "name": "openabstractions-panel",
  "title": "OpenAbstractions Panel",
  "description": "Open the native Panel credentials page.",
  "offers": {"version":"appmodel@1","commands":[]},
  "host": {"arguments":["-owned-host","-native","-quiet","-page","credentials"],"readiness_deadline_ms":15000},
  "script_host": false,
  "requests": [],
  "network": {"hosts":[]},
  "needs": {"files":[],"models":[]},
  "purpose": "",
  "verbs": [{"name":"open","class":"reveal","input_schema":{"type":"object","properties":{"page":{"type":"string","enum":["credentials"]}},"required":["page"],"additionalProperties":false}}]
}
`)
}
