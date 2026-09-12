package winsys

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procNotifyUnicastIpAddressChange = modIphlpapi.NewProc("NotifyUnicastIpAddressChange")
	procCancelMibChangeNotify2       = modIphlpapi.NewProc("CancelMibChangeNotify2")
)

// afUnspec asks for notifications on both IPv4 and IPv6.
const afUnspec = 0

// NetworkWatcher reports Windows unicast IP address changes, which is how
// AWGSocks notices a Wi-Fi reconnect, an Ethernet cable event, a DHCP lease
// change or a NAT-visible address change.
//
// It never changes any network setting; it only observes. The AmneziaWG UDP
// socket is rebound in response, which is the same thing the upstream Windows
// client does when the underlying network moves.
type NetworkWatcher struct {
	mu       sync.Mutex
	handle   windows.Handle
	callback uintptr
	events   chan struct{}
	started  bool
}

// watcherRegistry keeps the active watcher reachable from the C callback, which
// cannot carry a Go pointer in its context argument.
var (
	watcherMu sync.Mutex
	watcherCh chan struct{}
)

// NewNetworkWatcher creates an unstarted watcher.
func NewNetworkWatcher() *NetworkWatcher {
	return &NetworkWatcher{events: make(chan struct{}, 1)}
}

// Events returns the channel that receives a token on every address change.
// The channel has capacity one: bursts collapse into a single wake-up.
func (w *NetworkWatcher) Events() <-chan struct{} { return w.events }

// Start registers the notification callback with the IP Helper API.
func (w *NetworkWatcher) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started {
		return nil
	}
	if err := procNotifyUnicastIpAddressChange.Find(); err != nil {
		return err
	}

	watcherMu.Lock()
	watcherCh = w.events
	watcherMu.Unlock()

	cb := windows.NewCallback(func(callerContext uintptr, row uintptr, notificationType uint32) uintptr {
		watcherMu.Lock()
		ch := watcherCh
		watcherMu.Unlock()
		if ch != nil {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
		return 0
	})

	var handle windows.Handle
	ret, _, _ := procNotifyUnicastIpAddressChange.Call(
		uintptr(afUnspec),
		cb,
		0,
		0, // InitialNotification = FALSE
		uintptr(unsafe.Pointer(&handle)),
	)
	if ret != uintptr(windows.NO_ERROR) {
		return windows.Errno(ret)
	}

	w.handle = handle
	w.callback = cb
	w.started = true
	return nil
}

// Stop cancels the notification registration.
func (w *NetworkWatcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.started {
		return
	}
	if err := procCancelMibChangeNotify2.Find(); err == nil {
		procCancelMibChangeNotify2.Call(uintptr(w.handle))
	}
	w.started = false
	w.handle = 0

	watcherMu.Lock()
	watcherCh = nil
	watcherMu.Unlock()
}
