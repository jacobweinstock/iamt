// SPDX-License-Identifier: MPL-2.0

package internal

import (
	"context"
	"fmt"

	amtboot "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/boot"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/redirection"
	cimboot "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/boot"
)

// EnableRedirection turns on the AMT redirection service (IDER and SOL) and
// enables its network listener, so the redirection ports 16994/16995 accept
// connections. It is idempotent: a device already in this state is left
// unchanged.
//
// Both steps are required. RequestStateChange sets the administrative state,
// but the listener only accepts connections once ListenerEnabled is also true.
func (c *Client) EnableRedirection(_ context.Context) error {
	if _, err := c.Msg.AMT.RedirectionService.RequestStateChange(redirection.EnableIDERAndSOL); err != nil {
		return fmt.Errorf("iamt: enabling redirection service: %w", err)
	}

	cur, err := c.Msg.AMT.RedirectionService.Get()
	if err != nil {
		return fmt.Errorf("iamt: reading redirection service: %w", err)
	}
	resp := cur.Body.GetAndPutResponse
	if resp.ListenerEnabled && resp.EnabledState == redirection.IDERAndSOLAreEnabled {
		return nil
	}

	req := redirection.RedirectionRequest{
		CreationClassName:       resp.CreationClassName,
		ElementName:             resp.ElementName,
		EnabledState:            redirection.IDERAndSOLAreEnabled,
		ListenerEnabled:         true,
		Name:                    resp.Name,
		SystemCreationClassName: resp.SystemCreationClassName,
		SystemName:              resp.SystemName,
	}
	if _, err := c.Msg.AMT.RedirectionService.Put(req); err != nil {
		return fmt.Errorf("iamt: enabling redirection listener: %w", err)
	}
	return nil
}

// ArmIDERBoot arms a one-shot boot from the IDER CD device over WS-Man. This
// is what selects the redirected CD as the boot source and, crucially, lets
// AMT control Secure Boot for that boot: when enforceSecureBoot is false and
// the platform reports SecureBootControlEnabled, AMT disables Secure Boot for
// the IDER boot, so an unsigned image (a stock Talos ISO) boots without a
// Secure Boot violation.
//
// It deliberately does not call ChangeBootOrder: AMT rejects a boot-order
// change while UseIDER is set. The redirected disk is served separately over
// the redirection session.
func (c *Client) ArmIDERBoot(_ context.Context, enforceSecureBoot bool) error {
	// AMT refuses to set UseIDER while a boot source is configured (it reports
	// InvalidRepresentation on the Put). Clearing the boot order first is what
	// Intel's own console does before arming IDER.
	if _, err := c.Msg.CIM.BootConfigSetting.ChangeBootOrder(cimboot.Source("")); err != nil {
		return fmt.Errorf("iamt: clearing boot order before IDER: %w", err)
	}

	cur, err := c.Msg.AMT.BootSettingData.Get()
	if err != nil {
		return fmt.Errorf("iamt: reading boot setting data: %w", err)
	}
	resp := cur.Body.BootSettingDataGetResponse

	// Unlike the One-Click-Recovery path, an IDER Put must echo the device's
	// current settings back in full: a minimal object is rejected with
	// InvalidRepresentation. This mirrors Intel's own management console. Every
	// field is carried over from the read, then the IDER-relevant ones are
	// overridden and any OCR boot parameters are cleared.
	req := amtboot.BootSettingDataRequest{
		H:                        "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_BootSettingData",
		InstanceID:               bootSettingDataInstance,
		ElementName:              resp.ElementName,
		OwningEntity:             resp.OwningEntity,
		BIOSPause:                resp.BIOSPause,
		BIOSSetup:                resp.BIOSSetup,
		BootguardStatus:          resp.BootguardStatus,
		ConfigurationDataReset:   resp.ConfigurationDataReset,
		FirmwareVerbosity:        resp.FirmwareVerbosity,
		ForcedProgressEvents:     resp.ForcedProgressEvents,
		LockKeyboard:             resp.LockKeyboard,
		LockPowerButton:          resp.LockPowerButton,
		LockResetButton:          resp.LockResetButton,
		LockSleepButton:          resp.LockSleepButton,
		OptionsCleared:           resp.OptionsCleared,
		PlatformErase:            resp.PlatformErase,
		RPEEnabled:               resp.RPEEnabled,
		ReflashBIOS:              resp.ReflashBIOS,
		SecureBootControlEnabled: resp.SecureBootControlEnabled,
		SecureErase:              resp.SecureErase,
		UEFIHTTPSBootEnabled:     resp.UEFIHTTPSBootEnabled,
		UEFILocalPBABootEnabled:  resp.UEFILocalPBABootEnabled,
		UseSOL:                   resp.UseSOL,
		UseSafeMode:              resp.UseSafeMode,
		UserPasswordBypass:       resp.UserPasswordBypass,
		WinREBootEnabled:         resp.WinREBootEnabled,

		// IDER CD boot on the next reset, no OCR parameters.
		UseIDER:                 true,
		IDERBootDevice:          amtboot.CDBoot,
		BootMediaIndex:          0,
		EnforceSecureBoot:       enforceSecureBoot,
		UefiBootParametersArray: "",
		UefiBootNumberOfParams:  0,
	}
	if _, err := c.Msg.AMT.BootSettingData.Put(req); err != nil {
		return fmt.Errorf("iamt: writing IDER boot setting data: %w", err)
	}

	role, err := c.Msg.CIM.BootService.SetBootConfigRole(bootConfigInstance, roleIsNextSingleUse)
	if err != nil {
		return fmt.Errorf("iamt: arming IDER boot: %w", err)
	}
	if rv := role.Body.SetBootConfigRole_OUTPUT.ReturnValue; rv != 0 {
		return fmt.Errorf("iamt: arming IDER boot rejected with return value %d", rv)
	}
	return nil
}
