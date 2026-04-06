//go:build windows

package vkturnproxy

import "os/exec"

func setSysProcAttr(cmd *exec.Cmd) {}

func stopCmdProcess(cmd *exec.Cmd) error {
	return cmd.Process.Kill()
}
