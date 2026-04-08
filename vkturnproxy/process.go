package vkturnproxy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

func GetBinaryName() string {
	return fmt.Sprintf("vk-turn-proxy-server-%s-%s", runtime.GOOS, runtime.GOARCH)
}

func GetBinaryPath() string {
	return config.GetBinFolderPath() + "/" + GetBinaryName()
}

func GetReleaseAssetName() (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("vk-turn-proxy is supported only on linux, got %s", runtime.GOOS)
	}

	switch runtime.GOARCH {
	case "amd64":
		return "server-linux-amd64", nil
	case "arm64":
		return "server-linux-arm64", nil
	default:
		return "", fmt.Errorf("vk-turn-proxy has no release asset for linux/%s", runtime.GOARCH)
	}
}

type Spec struct {
	ID          int
	Remark      string
	Listen      string
	Connect     string
	SessionMode string
}

type HeartbeatState struct {
	Fingerprint string
	LastSeen    time.Time
	Online      bool
	Active      uint32
	Version     uint32
}

var heartbeatLinePattern = regexp.MustCompile(`protobuf heartbeat from .*: online=(true|false) active_streams=(\d+) version=(\d+) wg_fp="([^"]*)"`)

func (s Spec) Key() string {
	return strings.Join([]string{
		fmt.Sprintf("%d", s.ID),
		s.Listen,
		s.Connect,
		s.SessionMode,
	}, "\x00")
}

type Process struct {
	spec      Spec
	cmd       *exec.Cmd
	logWriter *logWriter
	exitErr   error
	startedAt time.Time
	mu        sync.RWMutex
}

func NewProcess(spec Spec) *Process {
	return &Process{
		spec:      spec,
		logWriter: &logWriter{id: spec.ID, remark: spec.Remark},
	}
}

func (p *Process) Spec() Spec {
	return p.spec
}

func (p *Process) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.cmd == nil || p.cmd.Process == nil {
		return false
	}
	return p.cmd.ProcessState == nil
}

func (p *Process) GetErr() error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.exitErr
}

func (p *Process) GetResult() string {
	if line := p.logWriter.LastLine(); line != "" {
		return line
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.exitErr != nil {
		return p.exitErr.Error()
	}
	return ""
}

func (p *Process) GetUptime() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.startedAt.IsZero() {
		return 0
	}
	return uint64(time.Since(p.startedAt).Seconds())
}

func (p *Process) HeartbeatSnapshot() map[string]HeartbeatState {
	return p.logWriter.HeartbeatSnapshot()
}

func (p *Process) Start() (err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil {
		return errors.New("vk-turn-proxy is already running")
	}

	args := []string{
		"-listen", p.spec.Listen,
		"-connect", p.spec.Connect,
	}
	if strings.TrimSpace(p.spec.SessionMode) != "" && p.spec.SessionMode != "auto" {
		args = append(args, "-session-mode", p.spec.SessionMode)
	}

	cmd := exec.Command(GetBinaryPath(), args...)
	cmd.Stdout = p.logWriter
	cmd.Stderr = p.logWriter
	setSysProcAttr(cmd)

	if err = cmd.Start(); err != nil {
		p.exitErr = err
		return err
	}

	p.cmd = cmd
	p.exitErr = nil
	p.startedAt = time.Now()

	go func() {
		waitErr := cmd.Wait()
		p.mu.Lock()
		defer p.mu.Unlock()
		if waitErr != nil {
			logger.Warningf("vk-turn-proxy[%d] exited: %v", p.spec.ID, waitErr)
		}
		p.exitErr = waitErr
	}()

	return nil
}

func (p *Process) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cmd == nil || p.cmd.Process == nil || p.cmd.ProcessState != nil {
		return nil
	}

	return stopCmdProcess(p.cmd)
}

type logWriter struct {
	id     int
	remark string
	mu     sync.RWMutex
	last   string
	beats  map[string]HeartbeatState
}

func (w *logWriter) Write(data []byte) (int, error) {
	message := strings.TrimSpace(string(bytes.TrimSpace(data)))
	if message == "" {
		return len(data), nil
	}
	for _, line := range strings.Split(message, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		w.mu.Lock()
		w.last = line
		w.mu.Unlock()
		w.recordHeartbeat(line)
		logger.Debugf("VKTURN[%d:%s] %s", w.id, w.remark, line)
	}
	return len(data), nil
}

func (w *logWriter) LastLine() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.last
}

func (w *logWriter) HeartbeatSnapshot() map[string]HeartbeatState {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if len(w.beats) == 0 {
		return nil
	}

	snapshot := make(map[string]HeartbeatState, len(w.beats))
	for fingerprint, state := range w.beats {
		snapshot[fingerprint] = state
	}
	return snapshot
}

func (w *logWriter) recordHeartbeat(line string) {
	matches := heartbeatLinePattern.FindStringSubmatch(line)
	if len(matches) != 5 {
		return
	}

	fingerprint := strings.TrimSpace(matches[4])
	if fingerprint == "" {
		return
	}

	active, err := strconv.ParseUint(matches[2], 10, 32)
	if err != nil {
		return
	}
	version, err := strconv.ParseUint(matches[3], 10, 32)
	if err != nil {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.beats == nil {
		w.beats = make(map[string]HeartbeatState)
	}
	w.beats[fingerprint] = HeartbeatState{
		Fingerprint: fingerprint,
		LastSeen:    time.Now(),
		Online:      matches[1] == "true",
		Active:      uint32(active),
		Version:     uint32(version),
	}
}

func EnsureBinaryExecutable() error {
	info, err := os.Stat(GetBinaryPath())
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", GetBinaryPath())
	}
	return os.Chmod(GetBinaryPath(), 0o755)
}
