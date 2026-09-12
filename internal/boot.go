package internal

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	amtboot "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/boot"
	cimboot "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/boot"
)

// Instance IDs AMT assigns to its singleton boot objects.
const (
	bootSettingDataInstance = "Intel(r) AMT:BootSettingData 0"
	bootConfigInstance      = "Intel(r) AMT: Boot Configuration 0"
)

// SetBootConfigRole role values.
const (
	// roleIsNextSingleUse arms an override for exactly one boot. AMT clears
	// the boot parameters once consumed, which is the only override semantics
	// the firmware actually offers.
	roleIsNextSingleUse = 1
	// roleIsNotNext clears any armed override.
	roleIsNotNext = 32768
)

// BootTarget names a boot device.
//
// The names follow Redfish vocabulary so callers bridging AMT to Redfish do
// not need a second translation table.
type BootTarget string

const (
	BootPxe       BootTarget = "Pxe"
	BootHdd       BootTarget = "Hdd"
	BootCd        BootTarget = "Cd"
	BootUefiHTTP  BootTarget = "UefiHttp"
	BootBiosSetup BootTarget = "BiosSetup"
)

// ErrUnsupportedBootTarget is returned for a target this device cannot boot.
var ErrUnsupportedBootTarget = errors.New("iamt: unsupported boot target")

// ErrVirtualMediaUnsupported is returned when the device firmware does not
// report ForceUEFIHTTPSBoot.
var ErrVirtualMediaUnsupported = errors.New("iamt: device does not support UEFI HTTPS boot")

var bootSources = map[BootTarget]cimboot.Source{
	BootPxe:      cimboot.PXE,
	BootHdd:      cimboot.HardDrive,
	BootCd:       cimboot.CD,
	BootUefiHTTP: cimboot.OCRUEFIHTTPS,
}

// SetPXE makes sure the node will pxe boot next time.
func (c *Client) SetPXE(ctx context.Context) error {
	return c.SetBootOverride(ctx, BootPxe)
}

// SetBootOverride arms a one-shot boot override.
//
// AMT requires three calls in order: write AMT_BootSettingData, select the
// source with ChangeBootOrder, then arm it with SetBootConfigRole. Doing fewer
// leaves the device booting normally while every call still reports success,
// which is the hardest failure here to notice.
//
// Only one-shot overrides exist. AMT clears the boot parameters once consumed,
// so a persistent override cannot be expressed.
func (c *Client) SetBootOverride(ctx context.Context, target BootTarget) error {
	if target == BootBiosSetup {
		return c.applyBootSettings(ctx, func(r *amtboot.BootSettingDataRequest) {
			r.BIOSSetup = true
		}, nil)
	}

	source, ok := bootSources[target]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnsupportedBootTarget, target)
	}
	return c.applyBootSettings(ctx, nil, &source)
}

// ClearBootOverride disarms any pending one-shot boot override.
func (c *Client) ClearBootOverride(_ context.Context) error {
	resp, err := c.Msg.CIM.BootService.SetBootConfigRole(bootConfigInstance, roleIsNotNext)
	if err != nil {
		return fmt.Errorf("iamt: clearing boot override: %w", err)
	}
	if rv := resp.Body.SetBootConfigRole_OUTPUT.ReturnValue; rv != 0 {
		return fmt.Errorf("iamt: clearing boot override rejected with return value %d", rv)
	}
	return nil
}

// InsertVirtualMedia arms a one-shot boot from an HTTPS-hosted image, using
// AMT's One Click Recovery UEFI HTTPS boot.
//
// AMT fetches the image itself, so imageURL must be reachable from the device
// and served with a certificate the device trusts. Neither can be checked from
// here: a device that distrusts the server boots normally and reports no
// error, so callers should confirm the boot actually happened.
//
// IDE redirection is deliberately not offered as an alternative. AMT 11 and
// later use USB-R rather than IDE-R for storage redirection, the redirection
// data plane is undocumented, and it would require holding a session open for
// the whole boot.
func (c *Client) InsertVirtualMedia(ctx context.Context, imageURL string, enforceSecureBoot bool) error {
	if err := validateImageURL(imageURL); err != nil {
		return err
	}

	caps, err := c.Msg.AMT.BootCapabilities.Get()
	if err != nil {
		return fmt.Errorf("iamt: reading boot capabilities: %w", err)
	}
	if !caps.Body.BootCapabilitiesGetResponse.ForceUEFIHTTPSBoot {
		return ErrVirtualMediaUnsupported
	}

	param, err := amtboot.NewStringParameter(amtboot.OCR_EFI_NETWORK_DEVICE_PATH, imageURL)
	if err != nil {
		return fmt.Errorf("iamt: encoding image URL as a boot parameter: %w", err)
	}
	buf, err := amtboot.CreateTLVBuffer([]amtboot.TLVParameter{param})
	if err != nil {
		return fmt.Errorf("iamt: building boot parameter buffer: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(buf)

	source := cimboot.OCRUEFIHTTPS
	return c.applyBootSettings(ctx, func(r *amtboot.BootSettingDataRequest) {
		r.UefiBootParametersArray = encoded
		r.UefiBootNumberOfParams = 1
		r.EnforceSecureBoot = enforceSecureBoot
	}, &source)
}

// EjectVirtualMedia clears a pending media boot.
func (c *Client) EjectVirtualMedia(ctx context.Context) error { return c.ClearBootOverride(ctx) }

// applyBootSettings performs the write/select/arm sequence. mutate customises
// the settings write; source, when non-nil, selects and arms a boot source.
//
// Every writable field is set explicitly rather than merged from the current
// value. AMT rejects writes that echo its read-only fields back (BIOSLastStatus,
// RPEEnabled and friends), and leaving a flag set from a previous override is
// how a device ends up booting the wrong thing.
func (c *Client) applyBootSettings(_ context.Context, mutate func(*amtboot.BootSettingDataRequest), source *cimboot.Source) error {
	cur, err := c.Msg.AMT.BootSettingData.Get()
	if err != nil {
		return fmt.Errorf("iamt: reading boot setting data: %w", err)
	}

	req := amtboot.BootSettingDataRequest{
		H:            "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_BootSettingData",
		InstanceID:   bootSettingDataInstance,
		ElementName:  cur.Body.BootSettingDataGetResponse.ElementName,
		OwningEntity: cur.Body.BootSettingDataGetResponse.OwningEntity,
	}
	if mutate != nil {
		mutate(&req)
	}

	if _, err := c.Msg.AMT.BootSettingData.Put(req); err != nil {
		return fmt.Errorf("iamt: writing boot setting data: %w", err)
	}

	if source == nil {
		return nil
	}

	order, err := c.Msg.CIM.BootConfigSetting.ChangeBootOrder(*source)
	if err != nil {
		return fmt.Errorf("iamt: setting boot order to %q: %w", *source, err)
	}
	if rv := order.Body.ChangeBootOrder_OUTPUT.ReturnValue; rv != 0 {
		return fmt.Errorf("iamt: boot order %q rejected with return value %d", *source, rv)
	}

	role, err := c.Msg.CIM.BootService.SetBootConfigRole(bootConfigInstance, roleIsNextSingleUse)
	if err != nil {
		return fmt.Errorf("iamt: arming boot override: %w", err)
	}
	if rv := role.Body.SetBootConfigRole_OUTPUT.ReturnValue; rv != 0 {
		return fmt.Errorf("iamt: arming boot override rejected with return value %d", rv)
	}
	return nil
}

// validateImageURL rejects images AMT cannot fetch, before any device state is
// touched.
//
// The scheme check is the important one: AMT performs HTTPS boot only, and an
// http:// URL is accepted by every call in the sequence before the device
// silently boots normally.
func validateImageURL(raw string) error {
	if raw == "" {
		return errors.New("iamt: image URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("iamt: parsing image URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("iamt: image URL must be https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("iamt: image URL must include a host")
	}
	return nil
}
