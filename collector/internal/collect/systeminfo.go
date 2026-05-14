package collect

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"runtime"
	"strings"
)

type systemInfo struct {
	OSVersion    string
	Architecture string
}

func CollectSystemInfo(ctx context.Context) systemInfo {
	info := systemInfo{}
	if runtime.GOOS != "windows" {
		return info
	}

	cmd := exec.CommandContext(ctx, "cmd", "/c", "ver")
	if output, err := cmd.Output(); err == nil {
		info.OSVersion = strings.TrimSpace(string(bytes.TrimSpace(output)))
	}

	wmic := exec.CommandContext(ctx, "wmic", "os", "get", "Caption,Version,BuildNumber,OSArchitecture", "/value")
	if output, err := wmic.Output(); err == nil {
		parsed := parseKeyValueLines(string(output))
		caption := parsed["Caption"]
		version := parsed["Version"]
		build := parsed["BuildNumber"]
		arch := parsed["OSArchitecture"]
		parts := make([]string, 0, 3)
		if caption != "" {
			parts = append(parts, caption)
		}
		if version != "" {
			parts = append(parts, "Version "+version)
		}
		if build != "" {
			parts = append(parts, "Build "+build)
		}
		if len(parts) > 0 {
			info.OSVersion = strings.Join(parts, " ")
		}
		if arch != "" {
			info.Architecture = arch
		}
	}

	return info
}

func parseKeyValueLines(input string) map[string]string {
	result := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(input))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		result[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return result
}
