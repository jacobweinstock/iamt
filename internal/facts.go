package internal

import (
	"context"
	"fmt"
	"strings"
)

// Control modes reported by IPS_HostBasedSetupService.
const (
	ControlModeNotProvisioned = "NotProvisioned"
	ControlModeClient         = "Client"
	ControlModeAdmin          = "Admin"
)

// Provisioning states reported by AMT_SetupAndConfigurationService.
const (
	ProvisioningPre  = "PreProvisioning"
	ProvisioningIn   = "InProvisioning"
	ProvisioningPost = "PostProvisioning"
)

// Firmware holds AMT firmware versions from CIM_SoftwareIdentity.
type Firmware struct {
	AMT      string
	Build    string
	SKU      string
	Recovery string
}

// BootCapabilities mirrors AMT_BootCapabilities: what this device can actually
// be told to boot. It gates what the Redfish layer advertises.
type BootCapabilities struct {
	PXE               bool
	HardDrive         bool
	CDDVD             bool
	UEFIHTTPS         bool
	IDER              bool
	SOL               bool
	BIOSSetup         bool
	SecureBootControl bool
}

// Redirection mirrors AMT_RedirectionService.
//
// EnabledState and ListenerEnabled are independent. A device reporting
// EnabledState 32771 (IDER+SOL) with ListenerEnabled false still has ports
// 16994/16995 closed.
type Redirection struct {
	EnabledState    int
	ListenerEnabled bool
}

// Redirection EnabledState values.
const (
	RedirectionDisabled   = 32768
	RedirectionIDEROnly   = 32769
	RedirectionSOLOnly    = 32770
	RedirectionIDERAndSOL = 32771
)

// Facts is everything the controller needs to know about a device that is not
// hardware inventory.
type Facts struct {
	PlatformGUID        string
	ProvisioningState   string
	ControlMode         string
	AllowedControlModes []string
	DigestRealm         string
	DNSSuffix           string
	Firmware            Firmware
	BootCapabilities    BootCapabilities
	Redirection         Redirection
}

// Provisioned reports whether the device has completed setup. An
// unprovisioned device has no admin credential and cannot be managed until it
// is onboarded out of band.
func (f Facts) Provisioned() bool { return f.ProvisioningState == ProvisioningPost }

// AllowsAdminControlMode reports whether host-based setup may enter Admin
// Control Mode on this platform. This is what determines whether cert-free
// ACM activation is possible, and is recorded so the question can be settled
// from real fleet data.
func (f Facts) AllowsAdminControlMode() bool {
	for _, m := range f.AllowedControlModes {
		if m == ControlModeAdmin {
			return true
		}
	}
	return false
}

// Facts collects device facts over WS-Man.
//
// Individual sub-reads are tolerated failing: an unprovisioned or partially
// configured device answers some classes and not others, and a partial picture
// is more useful than an error. The provisioning state and control mode are
// the exception -- without them the caller cannot decide anything.
func (c *Client) Facts(ctx context.Context) (*Facts, error) {
	f := &Facts{}

	setup, err := c.Msg.AMT.SetupAndConfigurationService.Get()
	if err != nil {
		return nil, fmt.Errorf("iamt: reading setup and configuration service: %w", err)
	}
	f.ProvisioningState = provisioningStateString(int(setup.Body.GetResponse.ProvisioningState))
	f.DNSSuffix = setup.Body.GetResponse.DhcpDNSSuffix

	if hbs, err := c.Msg.IPS.HostBasedSetupService.Get(); err == nil {
		f.ControlMode = controlModeString(int(hbs.Body.GetResponse.CurrentControlMode))
		for _, m := range hbs.Body.GetResponse.AllowedControlModes {
			f.AllowedControlModes = append(f.AllowedControlModes, controlModeString(int(m)))
		}
	}

	if gs, err := c.Msg.AMT.GeneralSettings.Get(); err == nil {
		f.DigestRealm = gs.Body.GetResponse.DigestRealm
	}

	if csp, err := c.Msg.CIM.ComputerSystemPackage.Get(); err == nil {
		f.PlatformGUID = normalizeGUID(csp.Body.GetResponse.PlatformGUID)
	}

	if bc, err := c.Msg.AMT.BootCapabilities.Get(); err == nil {
		r := bc.Body.BootCapabilitiesGetResponse
		f.BootCapabilities = BootCapabilities{
			PXE:               r.ForcePXEBoot,
			HardDrive:         r.ForceHardDriveBoot,
			CDDVD:             r.ForceCDorDVDBoot,
			UEFIHTTPS:         r.ForceUEFIHTTPSBoot,
			IDER:              r.IDER,
			SOL:               r.SOL,
			BIOSSetup:         r.BIOSSetup,
			SecureBootControl: r.AMTSecureBootControl,
		}
	}

	if rd, err := c.Msg.AMT.RedirectionService.Get(); err == nil {
		f.Redirection = Redirection{
			EnabledState:    int(rd.Body.GetAndPutResponse.EnabledState),
			ListenerEnabled: rd.Body.GetAndPutResponse.ListenerEnabled,
		}
	}

	f.Firmware = c.firmware(ctx)

	return f, nil
}

// firmware reads CIM_SoftwareIdentity, which reports versions as a flat list
// of InstanceID/VersionString pairs rather than typed fields.
func (c *Client) firmware(_ context.Context) Firmware {
	var fw Firmware

	enum, err := c.Msg.CIM.SoftwareIdentity.Enumerate()
	if err != nil {
		return fw
	}
	pull, err := c.Msg.CIM.SoftwareIdentity.Pull(enum.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return fw
	}

	for _, item := range pull.Body.PullResponse.SoftwareIdentityItems {
		switch item.InstanceID {
		case "AMT":
			fw.AMT = item.VersionString
		case "Build Number":
			fw.Build = item.VersionString
		case "Sku":
			fw.SKU = item.VersionString
		case "Recovery Version":
			fw.Recovery = item.VersionString
		}
	}
	return fw
}

func controlModeString(v int) string {
	switch v {
	case 0:
		return ControlModeNotProvisioned
	case 1:
		return ControlModeClient
	case 2:
		return ControlModeAdmin
	}
	return fmt.Sprintf("Unknown(%d)", v)
}

func provisioningStateString(v int) string {
	switch v {
	case 0:
		return ProvisioningPre
	case 1:
		return ProvisioningIn
	case 2:
		return ProvisioningPost
	}
	return fmt.Sprintf("Unknown(%d)", v)
}

// normalizeGUID renders AMT's 32-character hex PlatformGUID in canonical
// dashed form so it is usable as a Redfish resource id and a Kubernetes name
// component.
func normalizeGUID(s string) string {
	s = strings.TrimSpace(s)
	if len(s) != 32 {
		return strings.ToLower(s)
	}
	s = strings.ToLower(s)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}
