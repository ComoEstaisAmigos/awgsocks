package service

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/ComoEstaisAmigos/awgsocks/internal/logging"
	"github.com/ComoEstaisAmigos/awgsocks/internal/version"
)

// Windows power-event codes (winuser.h PBT_*).
const (
	pbtAPMSuspend           = 0x0004
	pbtAPMResumeSuspend     = 0x0007
	pbtAPMResumeAutomatic   = 0x0012
	pbtAPMPowerStatusChange = 0x000A
)

// acceptedControls is what the service tells the SCM it can handle. PowerEvent
// is required to get sleep/resume notifications; ParamChange lets an operator
// trigger a configuration reload from services.msc.
const acceptedControls = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent | svc.AcceptParamChange

// windowsService adapts Manager to the Windows service control protocol.
type windowsService struct {
	mgr *Manager
	log *logging.Logger
}

// startWaitHint is what the SCM is told to wait for during startup. Bringing
// the tunnel up can include resolving a hostname endpoint through the Windows
// resolver, which the upstream writer retries for up to 40 seconds.
const startWaitHint = 20000 // ms

// stopWaitHint bounds how long the SCM waits for a graceful shutdown.
const stopWaitHint = 20000 // ms

// Execute implements svc.Handler.
func (ws *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	checkpoint := uint32(0)
	changes <- svc.Status{State: svc.StartPending, CheckPoint: checkpoint, WaitHint: startWaitHint}

	// Startup can take a while, so progress is reported to the SCM regularly.
	// Without it the service looks hung and gets killed.
	startErr := make(chan error, 1)
	go func() { startErr <- ws.mgr.Start() }()

	progress := time.NewTicker(5 * time.Second)
	var err error
waitStart:
	for {
		select {
		case err = <-startErr:
			progress.Stop()
			break waitStart
		case <-progress.C:
			checkpoint++
			changes <- svc.Status{State: svc.StartPending, CheckPoint: checkpoint, WaitHint: startWaitHint}
		}
	}

	if err != nil {
		ws.log.Errorf("the service could not start: %v", err)
		// ssec = true marks this as a service specific error. A non-zero exit
		// code triggers the SCM recovery actions, that is, a restart.
		// svc.Run reports the stopped state itself.
		return true, 1
	}

	changes <- svc.Status{State: svc.Running, Accepts: acceptedControls}

loop:
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			break loop
		case svc.ParamChange:
			// Nobody is watching a return value here, so the report goes to the
			// log, which is the only place a service control manager reload
			// leaves a trace.
			msg, err := ws.mgr.Reload()
			if err != nil {
				ws.log.Errorf("reload failed: %v", err)
			} else if msg != "" {
				ws.log.Infof("reload: %s", strings.ReplaceAll(msg, "\n", "; "))
			}
		case svc.PowerEvent:
			switch c.EventType {
			case pbtAPMSuspend:
				ws.mgr.OnPowerSuspend()
			case pbtAPMResumeSuspend, pbtAPMResumeAutomatic:
				ws.mgr.OnPowerResume()
			case pbtAPMPowerStatusChange:
				// A power source change does not affect the network, so it is ignored.
			}
		default:
			ws.log.Debugf("unexpected service control request: %d", c.Cmd)
		}
	}

	// Shutdown happens after StopPending is reported; svc.Run reports the
	// stopped state itself once Execute returns.
	changes <- svc.Status{State: svc.StopPending, WaitHint: stopWaitHint}
	ws.mgr.Stop()
	return false, 0
}

// RunService runs AWGSocks under the Windows Service Control Manager.
func RunService(log *logging.Logger, appCfgPath string) error {
	mgr := NewManager(log, appCfgPath)
	if err := svc.Run(version.ServiceName, &windowsService{mgr: mgr, log: log}); err != nil {
		return fmt.Errorf("could not run the service: %w", err)
	}
	return nil
}

// IsWindowsService reports whether the process was started by the SCM.
func IsWindowsService() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}
