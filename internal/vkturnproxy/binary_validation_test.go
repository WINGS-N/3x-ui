package vkturnproxy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestValidateBinaryAcceptsHostExecutable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF validation is linux-only")
	}

	executablePath, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve executable path: %v", err)
	}

	if err := ValidateBinary(executablePath); err != nil {
		t.Fatalf("expected host executable to pass validation: %v", err)
	}
}

func TestValidateBinaryRejectsNonELF(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF validation is linux-only")
	}

	path := filepath.Join(t.TempDir(), "vk-turn-proxy")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	err := ValidateBinary(path)
	if err == nil {
		t.Fatal("expected non-ELF file to fail validation")
	}
	if !strings.Contains(err.Error(), "valid linux ELF executable") {
		t.Fatalf("expected ELF validation error, got %v", err)
	}
}
