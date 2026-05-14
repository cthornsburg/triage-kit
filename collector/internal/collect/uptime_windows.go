//go:build windows

package collect

import (
	"context"
	"syscall"
	"time"
)

type uptimeSnapshot struct {
	BootTime   time.Time
	Uptime     time.Duration
	Source     string
	Confidence string
}

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var getTickCount64 = kernel32.NewProc("GetTickCount64")

func collectUptime(ctx context.Context, collectedAt time.Time) (uptimeSnapshot, bool, string) {
	select {
	case <-ctx.Done():
		return uptimeSnapshot{Source: "Windows API GetTickCount64"}, false, ctx.Err().Error()
	default:
	}

	millis, _, err := getTickCount64.Call()
	if millis == 0 {
		if err != syscall.Errno(0) {
			return uptimeSnapshot{Source: "Windows API GetTickCount64"}, false, err.Error()
		}
		return uptimeSnapshot{Source: "Windows API GetTickCount64"}, false, "GetTickCount64 returned zero uptime"
	}
	uptime := time.Duration(uint64(millis)) * time.Millisecond
	return uptimeSnapshot{
		BootTime:   collectedAt.Add(-uptime),
		Uptime:     uptime,
		Source:     "Windows API GetTickCount64",
		Confidence: "high",
	}, true, ""
}
