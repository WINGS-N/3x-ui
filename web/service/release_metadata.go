package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	xrayReleaseTagSettingKey        = "xrayReleaseTag"
	vkTurnProxyReleaseTagSettingKey = "vkTurnProxyReleaseTag"
	releaseMetadataSuffix           = ".release"
	unknownInstalledRelease         = "Unknown"
)

func (s *SettingService) GetXrayReleaseTag() (string, error) {
	return s.getString(xrayReleaseTagSettingKey)
}

func (s *SettingService) SetXrayReleaseTag(value string) error {
	return s.setString(xrayReleaseTagSettingKey, strings.TrimSpace(value))
}

func (s *SettingService) GetVKTurnProxyReleaseTag() (string, error) {
	return s.getString(vkTurnProxyReleaseTagSettingKey)
}

func (s *SettingService) SetVKTurnProxyReleaseTag(value string) error {
	return s.setString(vkTurnProxyReleaseTagSettingKey, strings.TrimSpace(value))
}

func releaseMetadataPath(binaryPath string) string {
	return binaryPath + releaseMetadataSuffix
}

func readReleaseMetadata(binaryPath string) (string, error) {
	value, err := os.ReadFile(releaseMetadataPath(binaryPath))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(value)), nil
}

func writeReleaseMetadata(binaryPath string, tag string) error {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		_ = os.Remove(releaseMetadataPath(binaryPath))
		return nil
	}
	return os.WriteFile(releaseMetadataPath(binaryPath), []byte(tag+"\n"), 0o644)
}

func resolveInstalledReleaseTag(binaryPath string, getStored func() (string, error), setStored func(string) error) string {
	if tag, err := readReleaseMetadata(binaryPath); err == nil && tag != "" {
		if setStored != nil {
			_ = setStored(tag)
		}
		return tag
	}
	if getStored != nil {
		if tag, err := getStored(); err == nil && strings.TrimSpace(tag) != "" {
			return strings.TrimSpace(tag)
		}
	}
	return unknownInstalledRelease
}

func getGitHubLatestReleaseVersion(repo string) (string, error) {
	releaseURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(releaseURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		var errorResponse struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(bodyBytes, &errorResponse) == nil && errorResponse.Message != "" {
			return "", fmt.Errorf("GitHub API error: %s", errorResponse.Message)
		}
		return "", fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, resp.Status)
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}

	tag := strings.TrimSpace(release.TagName)
	if tag == "" {
		return "", fmt.Errorf("GitHub latest release tag for %s is empty", repo)
	}
	return tag, nil
}
