package vkturnproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogWriterHeartbeatSnapshotParsesFingerprint(t *testing.T) {
	writer := &logWriter{id: 1, remark: "test"}

	writer.recordHeartbeat("2026/04/08 12:34:56 protobuf heartbeat from 10.0.0.1:3456: online=true active_streams=2 version=3 proto_fp=\"sha256:test-fingerprint\"")

	snapshot := writer.HeartbeatSnapshot()
	if len(snapshot) != 1 {
		t.Fatalf("expected 1 heartbeat, got %d", len(snapshot))
	}

	state, ok := snapshot["sha256:test-fingerprint"]
	if !ok {
		t.Fatalf("expected fingerprint to be parsed, got %#v", snapshot)
	}
	if !state.Online {
		t.Fatal("expected heartbeat to be online")
	}
	if state.Active != 2 {
		t.Fatalf("expected active streams 2, got %d", state.Active)
	}
	if state.Version != 3 {
		t.Fatalf("expected version 3, got %d", state.Version)
	}
	if state.LastSeen.IsZero() {
		t.Fatal("expected heartbeat last seen timestamp to be set")
	}
}

func TestLogWriterHeartbeatSnapshotIgnoresEmptyFingerprint(t *testing.T) {
	writer := &logWriter{id: 1, remark: "test"}

	writer.recordHeartbeat("2026/04/08 12:34:56 protobuf heartbeat from 10.0.0.1:3456: online=true active_streams=2 version=3 proto_fp=\"\"")

	snapshot := writer.HeartbeatSnapshot()
	if len(snapshot) != 0 {
		t.Fatalf("expected no heartbeat snapshot, got %#v", snapshot)
	}
}

func TestLogWriterHeartbeatSnapshotKeepsLegacyFingerprintField(t *testing.T) {
	writer := &logWriter{id: 1, remark: "test"}

	writer.recordHeartbeat("2026/04/08 12:34:56 protobuf heartbeat from 10.0.0.1:3456: online=true active_streams=2 version=3 wg_fp=\"sha256:legacy-fingerprint\"")

	snapshot := writer.HeartbeatSnapshot()
	if _, ok := snapshot["sha256:legacy-fingerprint"]; !ok {
		t.Fatalf("expected legacy fingerprint to be parsed, got %#v", snapshot)
	}
}

func TestDecorateExecStartErrorHintsExistingBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vk-turn-proxy")
	if err := os.WriteFile(path, []byte("not-a-real-binary"), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	err := decorateExecStartError(path, &os.PathError{Op: "fork/exec", Path: path, Err: os.ErrNotExist})
	if err == nil {
		t.Fatal("expected decorated error")
	}
	if !strings.Contains(err.Error(), "host architecture") {
		t.Fatalf("expected architecture hint in error, got %v", err)
	}
}
