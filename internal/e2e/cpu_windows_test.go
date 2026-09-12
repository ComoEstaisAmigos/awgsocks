//go:build windows

package e2e

import (
	"time"

	"golang.org/x/sys/windows"
)

// processCPUTime reports cumulative user plus kernel CPU time for the current
// test process. It includes all AmneziaWG, gVisor and SOCKS5 goroutines.
func processCPUTime() time.Duration {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user); err != nil {
		return 0
	}
	return time.Duration(kernel.Nanoseconds() + user.Nanoseconds())
}
