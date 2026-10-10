package logging

import (
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// DeviceLogger adapts this package's Logger to the amneziawg-go device.Logger
// interface so that the embedded AmneziaWG implementation writes into the same
// rotating, redacted log as the rest of AWGSocks.
//
// amneziawg-go's own NewLogger writes to stdout with no redaction, which would
// be wrong for a Windows service, so it is deliberately not used.
func DeviceLogger(l *Logger, prefix string) *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			l.Debugf(prefix+format, args...)
		},
		Errorf: func(format string, args ...any) {
			l.Errorf(prefix+format, args...)
		},
	}
}
