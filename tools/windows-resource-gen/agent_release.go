package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const agentReleaseRC = "LANGUAGE 0, 0\r\nOA_AGENT_RELEASE RCDATA \"agent-release.json\"\r\n"

// Compile before the existing signing step: .rsrc is part of the signed PE
// image. Resource loading needs no entry point or helper execution.
func buildAgentReleaseObject(payload, output, arch, vcvars string) error {
	return buildNativeDataObject(payload, output, arch, vcvars, "OA_AGENT_RELEASE", "")
}

func buildNativeDataObject(payload, output, arch, vcvars, resource, panelDir string) error {
	if resource != "OA_AGENT_RELEASE" && resource != "OA_INSTALLER_GATEWAY_HISTORY" {
		return fmt.Errorf("unknown native data resource")
	}
	if runtime.GOOS != "windows" {
		return fmt.Errorf("agent release resource compilation needs Windows SDK tools")
	}
	if resource == "OA_INSTALLER_GATEWAY_HISTORY" && !filepath.IsAbs(panelDir) {
		return fmt.Errorf("installer history requires the existing absolute Panel resource directory")
	}
	if !filepath.IsAbs(payload) || !filepath.IsAbs(output) || filepath.Base(output) != "rsrc_windows_"+arch+".syso" || (arch != "amd64" && arch != "arm64") {
		return fmt.Errorf("agent release requires absolute JSON and fresh rsrc_windows_ARCH.syso paths")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		return fmt.Errorf("agent release object output must be absent")
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(output)
		}
	}()
	body, err := os.ReadFile(payload)
	if err != nil {
		return err
	}
	if len(body) == 0 || len(body) > 262144 || !json.Valid(body) {
		return fmt.Errorf("agent release document must be bounded JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(body, canonical) {
		return fmt.Errorf("agent release document must be canonical compact JSON")
	}
	if vcvars == "" {
		vcvars, err = findVCVars64()
		if err != nil {
			return err
		}
	}
	if _, err := os.Stat(vcvars); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(filepath.Dir(output), ".agent-release-resource-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	recipe := strings.Replace(agentReleaseRC, "OA_AGENT_RELEASE", resource, 1)
	if resource == "OA_INSTALLER_GATEWAY_HISTORY" {
		if _, err := os.Stat(filepath.Join(panelDir, "panel.rc")); err != nil {
			return err
		}
		recipe = fmt.Sprintf("#include \"%s\"\r\nLANGUAGE 0, 0\r\nOA_INSTALLER_GATEWAY_HISTORY RCDATA \"%s\"\r\n", filepath.ToSlash(filepath.Join(panelDir, "panel.rc")), filepath.ToSlash(filepath.Join(dir, "agent-release.json")))
	}
	for name, body := range map[string][]byte{"agent-release.json": body, "agent-release.rc": []byte(recipe)} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
			return err
		}
	}
	machine := "X64"
	if arch == "arm64" {
		machine = "ARM64"
	}
	bat := fmt.Sprintf("@echo off\r\ncall \"%s\" >nul || exit /b 1\r\nrc.exe /nologo /fo \"%s\" \"%s\" || exit /b 1\r\ncvtres.exe /NOLOGO /MACHINE:%s /OUT:\"%s\" \"%s\" || exit /b 1\r\n", vcvars, filepath.Join(dir, "agent-release.res"), filepath.Join(dir, "agent-release.rc"), machine, output, filepath.Join(dir, "agent-release.res"))
	path := filepath.Join(dir, "compile.cmd")
	if err := os.WriteFile(path, []byte(bat), 0600); err != nil {
		return err
	}
	cmd := exec.Command("cmd.exe", "/c", path)
	cmd.Dir = dir
	if panelDir != "" {
		cmd.Dir = panelDir
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("agent release resource compiler: %w\n%s", err, out)
	}
	if err := sanitizeCOFF(output); err != nil {
		return err
	}
	complete = true
	return nil
}
