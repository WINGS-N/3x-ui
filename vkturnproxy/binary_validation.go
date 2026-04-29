package vkturnproxy

import (
	"debug/elf"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

func ValidateBinary(path string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("vk-turn-proxy custom binary validation is supported only on linux, got %s", runtime.GOOS)
	}

	file, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("vk-turn-proxy binary is not a valid linux ELF executable: %w", err)
	}
	defer file.Close()

	expectedMachine, err := expectedELFMachine()
	if err != nil {
		return err
	}
	if file.Machine != expectedMachine {
		return fmt.Errorf("vk-turn-proxy binary architecture mismatch: expected %s, got %s", elfMachineName(expectedMachine), elfMachineName(file.Machine))
	}
	if file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return fmt.Errorf("vk-turn-proxy binary has unsupported ELF type %s", file.Type.String())
	}

	interpreterPath, err := readELFInterpreter(file)
	if err != nil {
		return err
	}
	if interpreterPath == "" {
		return nil
	}
	if _, err := os.Stat(interpreterPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("vk-turn-proxy binary requires missing loader %q", interpreterPath)
		}
		return fmt.Errorf("check vk-turn-proxy binary loader %q: %w", interpreterPath, err)
	}
	return nil
}

func expectedELFMachine() (elf.Machine, error) {
	switch runtime.GOARCH {
	case "amd64":
		return elf.EM_X86_64, nil
	case "arm64":
		return elf.EM_AARCH64, nil
	default:
		return 0, fmt.Errorf("vk-turn-proxy binary validation is unsupported for linux/%s", runtime.GOARCH)
	}
}

func elfMachineName(machine elf.Machine) string {
	switch machine {
	case elf.EM_X86_64:
		return "amd64"
	case elf.EM_AARCH64:
		return "arm64"
	default:
		return fmt.Sprintf("machine(%d)", machine)
	}
}

func readELFInterpreter(file *elf.File) (string, error) {
	for _, prog := range file.Progs {
		if prog.Type != elf.PT_INTERP {
			continue
		}
		raw, err := io.ReadAll(prog.Open())
		if err != nil {
			return "", fmt.Errorf("read vk-turn-proxy ELF interpreter: %w", err)
		}
		return strings.TrimRight(string(raw), "\x00"), nil
	}
	return "", nil
}
