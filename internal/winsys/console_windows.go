package winsys

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcessList = modKernel32.NewProc("GetConsoleProcessList")
)

// OwnsConsole reports whether this process is the only one attached to its
// console.
//
// That is exactly what a double click in Explorer produces: Explorer creates a
// console for this process alone and tears it down the instant the process
// returns, so whatever was printed disappears before anyone can read it.
// Started from an existing command prompt there are at least two processes
// attached, the shell and this one, and the output stays on screen.
//
// A process with no console at all, which is how the service control manager
// starts the service, reports false.
func OwnsConsole() bool {
	var pids [4]uint32
	// GetConsoleProcessList returns the number of attached processes, or the
	// number required when the buffer is too small. Either way a result of one
	// means this process is alone. A failure returns zero.
	n, _, _ := procGetConsoleProcessList.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids)),
	)
	return n == 1
}
