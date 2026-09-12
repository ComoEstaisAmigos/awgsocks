//go:build !windows

package e2e

import "time"

func processCPUTime() time.Duration { return 0 }
