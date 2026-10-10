package awg

import (
	"context"
	"errors"
	"fmt"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"github.com/ComoEstaisAmigos/awgsocks/internal/config"
	"github.com/ComoEstaisAmigos/awgsocks/internal/logging"
)

// DryRun proves that a configuration is acceptable to the pinned upstream
// AmneziaWG implementation, without sending a single packet.
//
// It builds a throwaway userspace stack and device, applies the configuration
// over UAPI and tears everything down again. This is the only way to validate
// parameters whose grammar lives inside the upstream device, such as the I1-I5
// obfuscation chain descriptions and the rule that H1-H4 ranges must not
// overlap. The device is never brought up, so no UDP socket is opened and no
// handshake is attempted.
func DryRun(ctx context.Context, log *logging.Logger, cfg *config.Tunnel) error {
	if cfg == nil {
		return errors.New("the configuration is empty")
	}

	uapi, err := toUAPI(ctx, cfg)
	if err != nil {
		return err
	}

	tunDev, _, err := netstack.CreateNetTUN(cfg.Addresses, cfg.DNS, cfg.MTU)
	if err != nil {
		return fmt.Errorf("could not create the userspace network stack: %w", err)
	}

	// The upstream device logs at DEBUG only, through the same redaction
	// filter as everything else. The device is never brought up during a dry
	// run, so the bind opens no socket and the simplest one will do.
	dev := device.NewDevice(tunDev, newBind(BindStd), logging.DeviceLogger(log, "dry run: "))
	defer dev.Close()

	if err := dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("the AmneziaWG configuration was rejected by the upstream device: %w", err)
	}
	if _, err := peerKeys(cfg); err != nil {
		return err
	}
	return nil
}
