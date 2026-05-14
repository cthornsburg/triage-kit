//go:build !windows

package collect

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type uptimeSnapshot struct {
	BootTime   time.Time
	Uptime     time.Duration
	Source     string
	Confidence string
}

func collectUptime(ctx context.Context, collectedAt time.Time) (uptimeSnapshot, bool, string) {
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if seconds, parseErr := strconv.ParseFloat(fields[0], 64); parseErr == nil && seconds >= 0 {
				uptime := time.Duration(seconds * float64(time.Second))
				return uptimeSnapshot{
					BootTime:   collectedAt.Add(-uptime),
					Uptime:     uptime,
					Source:     "/proc/uptime",
					Confidence: "medium",
				}, true, ""
			}
		}
	}

	cmd := exec.CommandContext(ctx, "sysctl", "-n", "kern.boottime")
	if output, err := cmd.Output(); err == nil {
		bootTime, ok := parseDarwinBootTime(string(output))
		if ok && !bootTime.IsZero() {
			uptime := collectedAt.Sub(bootTime)
			if uptime >= 0 {
				return uptimeSnapshot{
					BootTime:   bootTime,
					Uptime:     uptime,
					Source:     "sysctl kern.boottime",
					Confidence: "medium",
				}, true, ""
			}
		}
	}

	return uptimeSnapshot{Source: "platform fallback uptime lookup"}, false, "boot time/uptime unavailable from /proc/uptime or sysctl kern.boottime"
}

func parseDarwinBootTime(input string) (time.Time, bool) {
	re := regexp.MustCompile(`sec\s*=\s*(\d+)`)
	match := re.FindStringSubmatch(input)
	if len(match) != 2 {
		return time.Time{}, false
	}
	seconds, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0).UTC(), true
}
