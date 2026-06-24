package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/vkturnproxy"
)

const xrayReleaseRepo = "WINGS-N/Xray-core"

func getGitHubReleaseVersions(repo string) ([]string, error) {
	releasesURL := fmt.Sprintf("https://api.github.com/repos/%s/releases", repo)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(releasesURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check HTTP status code - GitHub API returns object instead of array on error
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		var errorResponse struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(bodyBytes, &errorResponse) == nil && errorResponse.Message != "" {
			return nil, fmt.Errorf("GitHub API error: %s", errorResponse.Message)
		}
		return nil, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, resp.Status)
	}

	var releases []Release
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, err
	}

	var versions []string
	for _, release := range releases {
		if tag := strings.TrimSpace(release.TagName); tag != "" {
			versions = append(versions, tag)
		}
	}
	return versions, nil
}

func (s *ServerService) GetVKTurnProxyVersions() ([]string, error) {
	return getGitHubReleaseVersions(vkTurnProxyReleaseRepo)
}

func (s *ServerService) GetVKTurnProxyStatus() VKTurnProxyRuntimeStatus {
	return VKTurnProxyRuntime().GetStatus()
}

func (s *ServerService) StartVKTurnProxyService() error {
	if err := VKTurnProxyRuntime().StartAll(); err != nil {
		logger.Error("start vk-turn-proxy failed:", err)
		return err
	}
	return nil
}

func (s *ServerService) StopVKTurnProxyService() error {
	if err := VKTurnProxyRuntime().StopAll(); err != nil {
		logger.Error("stop vk-turn-proxy failed:", err)
		return err
	}
	return nil
}

func (s *ServerService) RestartVKTurnProxyService() error {
	if err := VKTurnProxyRuntime().RestartAll(); err != nil {
		logger.Error("restart vk-turn-proxy failed:", err)
		return err
	}
	return nil
}

func (s *ServerService) UpdateVKTurnProxy(version string) error {
	if err := VKTurnProxyRuntime().UpdateBinary(version); err != nil {
		logger.Error("update vk-turn-proxy failed:", err)
		return err
	}
	return nil
}

func (s *ServerService) UploadVKTurnProxyBinary(file multipart.File) error {
	if err := VKTurnProxyRuntime().UploadCustomBinary(file); err != nil {
		logger.Error("upload vk-turn-proxy binary failed:", err)
		return err
	}
	return nil
}

func (s *ServerService) GetVKTurnProxyLogs(count string, level string) []string {
	countInt, err := strconv.Atoi(count)
	if err != nil || countInt < 1 {
		countInt = 20
	}

	if logs := tailMatchingLogLines(filepath.Join(config.GetLogFolder(), logger.LogFileName), countInt, level, "VKTURN["); len(logs) > 0 {
		return logs
	}

	allLogs := logger.GetLogs(2000, level)
	filtered := make([]string, 0, min(countInt, len(allLogs)))
	for _, line := range allLogs {
		if !strings.Contains(line, "VKTURN[") {
			continue
		}
		filtered = append(filtered, line)
		if len(filtered) >= countInt {
			break
		}
	}
	return filtered
}

func (s *ServerService) getInstalledVKTurnProxyReleaseTag() string {
	return resolveInstalledReleaseTag(
		vkturnproxy.GetBinaryPath(),
		s.settingService.GetVKTurnProxyReleaseTag,
		s.settingService.SetVKTurnProxyReleaseTag,
	)
}

// tailMatchingLogLines returns up to limit matching lines (newest first) from
// the end of the log file. It reads the file backwards in fixed chunks and
// stops as soon as it has collected limit matches, so a multi-megabyte 3xui.log
// no longer has to be scanned from the start on every poll - that whole-file
// scan was why opening the vk-turn-proxy log view took so long.
func tailMatchingLogLines(path string, limit int, maxLevel string, needle string) []string {
	if limit < 1 {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil
	}

	const chunkSize = 64 * 1024
	matches := make([]string, 0, limit)
	var remainder []byte
	pos := stat.Size()
	for pos > 0 && len(matches) < limit {
		readSize := int64(chunkSize)
		if pos < readSize {
			readSize = pos
		}
		pos -= readSize
		block := make([]byte, readSize)
		if _, err := file.ReadAt(block, pos); err != nil {
			break
		}
		data := append(block, remainder...)
		lines := bytes.Split(data, []byte{'\n'})
		if pos > 0 {
			// The first segment may be the tail of a line that continues into
			// the previous chunk; carry it over to the next (earlier) read.
			remainder = lines[0]
			lines = lines[1:]
		} else {
			remainder = nil
		}
		for i := len(lines) - 1; i >= 0 && len(matches) < limit; i-- {
			line := strings.TrimSpace(string(lines[i]))
			if line == "" || !strings.Contains(line, needle) || !panelLogMatchesLevel(line, maxLevel) {
				continue
			}
			matches = append(matches, line)
		}
	}
	return matches
}

func panelLogMatchesLevel(line string, maxLevel string) bool {
	requested := panelLogLevelRank(maxLevel)
	if requested == 0 {
		requested = panelLogLevelRank("debug")
	}

	fields := strings.Fields(line)
	if len(fields) < 3 {
		return true
	}
	lineLevel := panelLogLevelRank(fields[2])
	if lineLevel == 0 {
		return true
	}
	return lineLevel <= requested
}

func panelLogLevelRank(level string) int {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "CRITICAL", "CRIT", "ERROR", "ERR":
		return 1
	case "WARNING", "WARN":
		return 2
	case "NOTICE":
		return 3
	case "INFO":
		return 4
	case "DEBUG":
		return 5
	default:
		return 0
	}
}
