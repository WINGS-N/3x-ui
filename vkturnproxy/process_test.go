package vkturnproxy

import "testing"

func TestLogWriterHeartbeatSnapshotParsesFingerprint(t *testing.T) {
	writer := &logWriter{id: 1, remark: "test"}

	writer.recordHeartbeat("2026/04/08 12:34:56 protobuf heartbeat from 10.0.0.1:3456: online=true active_streams=2 version=3 wg_fp=\"sha256:test-fingerprint\"")

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

	writer.recordHeartbeat("2026/04/08 12:34:56 protobuf heartbeat from 10.0.0.1:3456: online=true active_streams=2 version=3 wg_fp=\"\"")

	snapshot := writer.HeartbeatSnapshot()
	if len(snapshot) != 0 {
		t.Fatalf("expected no heartbeat snapshot, got %#v", snapshot)
	}
}
