package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/op/go-logging"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// writePanelLog seeds the panel log file the file backend writes, in the same
// "2006/01/02 15:04:05 LEVEL - message" format GetLogs returns to the viewer.
func writePanelLog(t *testing.T, lines []string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XUI_LOG_FOLDER", dir)
	path := filepath.Join(dir, logger.LogFileName)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write panel log: %v", err)
	}
}

// TestGetLogs_TailsPanelFile verifies the non-syslog viewer sources up to count
// lines from the panel log file (newest first), so picking 500 returns real
// history instead of only the in-memory ring buffer's current contents.
func TestGetLogs_TailsPanelFile(t *testing.T) {
	const total = 600
	lines := make([]string, 0, total)
	for i := range total {
		lines = append(lines, fmt.Sprintf("2026/06/24 15:04:%02d INFO - line %d", i%60, i))
	}
	writePanelLog(t, lines)

	s := &ServerService{}
	got := s.GetLogs("500", "info", "false")

	if len(got) != 500 {
		t.Fatalf("GetLogs(500) returned %d lines, want 500", len(got))
	}
	// Newest first: the last seeded line must lead the output.
	if want := lines[total-1]; got[0] != want {
		t.Errorf("first line = %q, want newest %q", got[0], want)
	}
	if want := lines[total-500]; got[len(got)-1] != want {
		t.Errorf("last line = %q, want %q", got[len(got)-1], want)
	}
}

// TestGetLogs_FileLevelFilter verifies file-tailed lines honour the same
// "severity at or above the requested level" filter the in-memory path applies.
func TestGetLogs_FileLevelFilter(t *testing.T) {
	lines := []string{
		"2026/06/24 15:04:01 DEBUG - d0",
		"2026/06/24 15:04:02 INFO - i0",
		"2026/06/24 15:04:03 WARNING - w0",
		"2026/06/24 15:04:04 ERROR - e0",
		"2026/06/24 15:04:05 DEBUG - d1",
	}
	writePanelLog(t, lines)
	s := &ServerService{}

	// At info level, DEBUG lines are dropped; the rest survive (newest first).
	got := s.GetLogs("100", "info", "false")
	if len(got) != 3 {
		t.Fatalf("info filter returned %d lines, want 3: %v", len(got), got)
	}
	for _, line := range got {
		if strings.Contains(line, "DEBUG") {
			t.Errorf("info filter leaked a DEBUG line: %q", line)
		}
	}

	// At err level only ERROR (and more severe) lines remain.
	gotErr := s.GetLogs("100", "err", "false")
	if len(gotErr) != 1 || !strings.Contains(gotErr[0], "ERROR - e0") {
		t.Errorf("err filter = %v, want only the ERROR line", gotErr)
	}
}

// TestGetLogs_FallsBackToBuffer verifies a missing log file falls back to the
// in-memory buffer so the viewer never regresses to empty.
func TestGetLogs_FallsBackToBuffer(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XUI_LOG_FOLDER", dir)

	// Seed the in-memory buffer through the real logging path, then remove the
	// file backend's output so only the buffer remains to satisfy the request.
	logger.InitLogger(logging.DEBUG)
	logger.Info("fallback marker line")
	logger.CloseLogger()
	if err := os.Remove(filepath.Join(dir, logger.LogFileName)); err != nil {
		t.Fatalf("remove panel log: %v", err)
	}

	got := (&ServerService{}).GetLogs("100", "info", "false")
	if len(got) == 0 {
		t.Fatal("expected fallback buffer line, got none")
	}
	if !strings.Contains(got[0], "fallback marker line") {
		t.Errorf("fallback line = %q, want the buffered marker", got[0])
	}
}
