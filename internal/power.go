package internal

import (
	"context"
	"fmt"
	"strconv"

	cimpower "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/power"
)

// PowerState is a CIM power state value.
//
// The numbering is the canonical DMTF valuemap for
// CIM_PowerManagementService.RequestPowerStateChange. It is declared here
// rather than taken from go-wsman-messages because that library's constant
// names do not line up with the canonical map -- its PowerOffHard is 8, which
// the DMTF map calls Power Off - Soft. Values, not names, are what reach the
// device, so the canonical numbering is kept and the names describe what the
// numbers actually mean.
type PowerState int

// https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/HTMLDocuments/WS-Management_Class_Reference/CIM_AssociatedPowerManagementService.htm
const (
	PowerUnknown              PowerState = 0
	PowerOther                PowerState = 1
	PowerStateOn              PowerState = 2
	PowerSleepLight           PowerState = 3
	PowerSleepDeep            PowerState = 4
	PowerCycleOffSoft         PowerState = 5
	PowerOffHard              PowerState = 6
	PowerHibernateOffSoft     PowerState = 7
	PowerOffSoft              PowerState = 8
	PowerCycleOffHard         PowerState = 9
	PowerMasterBusReset       PowerState = 10
	PowerDiagnosticInterrupt  PowerState = 11
	PowerOffSoftGraceful      PowerState = 12
	PowerOffHardGraceful      PowerState = 13
	PowerMasterBusResetGrace  PowerState = 14
	PowerCycleOffSoftGraceful PowerState = 15
	PowerCycleOffHardGraceful PowerState = 16
)

// String renders a power state for logs. The previous implementation used
// stringer-generated code; a hand-written method keeps the codegen toolchain
// out of the build for one small type.
func (p PowerState) String() string {
	switch p {
	case PowerUnknown:
		return "Unknown"
	case PowerOther:
		return "Other"
	case PowerStateOn:
		return "On"
	case PowerSleepLight:
		return "SleepLight"
	case PowerSleepDeep:
		return "SleepDeep"
	case PowerCycleOffSoft:
		return "PowerCycleOffSoft"
	case PowerOffHard:
		return "OffHard"
	case PowerHibernateOffSoft:
		return "HibernateOffSoft"
	case PowerOffSoft:
		return "OffSoft"
	case PowerCycleOffHard:
		return "PowerCycleOffHard"
	case PowerMasterBusReset:
		return "MasterBusReset"
	case PowerDiagnosticInterrupt:
		return "DiagnosticInterrupt"
	case PowerOffSoftGraceful:
		return "OffSoftGraceful"
	case PowerOffHardGraceful:
		return "OffHardGraceful"
	case PowerMasterBusResetGrace:
		return "MasterBusResetGraceful"
	case PowerCycleOffSoftGraceful:
		return "PowerCycleOffSoftGraceful"
	case PowerCycleOffHardGraceful:
		return "PowerCycleOffHardGraceful"
	default:
		return "PowerState(" + strconv.Itoa(int(p)) + ")"
	}
}

// Status is the observed power state of a device.
type Status struct {
	// PowerState is the current state.
	PowerState PowerState
	// RequestedPowerState is the state the device is transitioning to.
	RequestedPowerState PowerState
	// AvailableRequestedPowerStates lists the transitions the device says it
	// will accept. Some AMT versions report this empty; see PowerOff.
	AvailableRequestedPowerStates []PowerState
}

// PoweredOn reports whether the host is on.
func (s Status) PoweredOn() bool { return s.PowerState == PowerStateOn }

// Status reads the current power status.
func (c *Client) Status(_ context.Context) (Status, error) {
	resp, err := c.Msg.CIM.AssociatedPowerManagementService.Get()
	if err != nil {
		return Status{}, fmt.Errorf("iamt: reading power status: %w", err)
	}

	body := resp.Body.AssociatedPowerManagementService
	status := Status{
		PowerState:                    PowerState(body.PowerState),
		RequestedPowerState:           PowerState(body.RequestedPowerState),
		AvailableRequestedPowerStates: make([]PowerState, 0, len(body.AvailableRequestedPowerStates)),
	}
	for _, s := range body.AvailableRequestedPowerStates {
		status.AvailableRequestedPowerStates = append(status.AvailableRequestedPowerStates, PowerState(s))
	}
	return status, nil
}

// IsPoweredOn checks current power state.
func (c *Client) IsPoweredOn(ctx context.Context) (bool, error) {
	status, err := c.Status(ctx)
	if err != nil {
		return false, err
	}
	c.Log.V(1).Info("states",
		"currentState", status.PowerState,
		"availableStates", status.AvailableRequestedPowerStates)
	return status.PoweredOn(), nil
}

// PowerOn will power on a given machine.
func (c *Client) PowerOn(ctx context.Context) error {
	isOn, err := c.IsPoweredOn(ctx)
	if err != nil {
		return err
	}
	if isOn {
		return nil
	}
	return c.RequestPowerState(ctx, PowerStateOn)
}

// PowerOff will power off a given machine.
//
// It prefers the gentlest transition the device advertises. When the device
// advertises none -- some AMT versions report AvailableRequestedPowerStates
// empty -- each candidate is tried in turn rather than giving up, because an
// empty list means "unknown", not "nothing works".
func (c *Client) PowerOff(ctx context.Context) error {
	status, err := c.Status(ctx)
	if err != nil {
		return err
	}
	if !status.PoweredOn() {
		return nil
	}

	if request := selectState(powerOffStates(), status.AvailableRequestedPowerStates); request != PowerUnknown {
		return c.RequestPowerState(ctx, request)
	}

	if len(status.AvailableRequestedPowerStates) == 0 {
		var lastErr error
		for _, s := range powerOffStates() {
			if lastErr = c.RequestPowerState(ctx, s); lastErr == nil {
				return nil
			}
			c.Log.V(1).Info("power off state rejected, trying next", "state", s, "err", lastErr)
		}
		return fmt.Errorf("iamt: all power off states failed for empty AvailableRequestedPowerStates, last error: %w", lastErr)
	}

	return fmt.Errorf("iamt: there is no implemented transition state to power off the machine from the current machine state %d. available states are: %v",
		status.PowerState, status.AvailableRequestedPowerStates)
}

// PowerCycle will power cycle a given machine.
func (c *Client) PowerCycle(ctx context.Context) error {
	status, err := c.Status(ctx)
	if err != nil {
		return err
	}
	if !status.PoweredOn() {
		return c.PowerOn(ctx)
	}

	if request := selectState(powerCycleStates(), status.AvailableRequestedPowerStates); request != PowerUnknown {
		return c.RequestPowerState(ctx, request)
	}

	if len(status.AvailableRequestedPowerStates) == 0 {
		var lastErr error
		for _, s := range powerCycleStates() {
			if lastErr = c.RequestPowerState(ctx, s); lastErr == nil {
				return nil
			}
			c.Log.V(1).Info("power cycle state rejected, trying next", "state", s, "err", lastErr)
		}
		return fmt.Errorf("iamt: all power cycle states failed for empty AvailableRequestedPowerStates, last error: %w", lastErr)
	}

	return fmt.Errorf("iamt: there is no implemented transition state to power cycle the machine from the current machine state %d. available states are: %v",
		status.PowerState, status.AvailableRequestedPowerStates)
}

// RequestPowerState asks the device for a specific transition.
//
// A zero return value means AMT accepted the request, not that the host
// completed the transition; callers that care should poll Status.
func (c *Client) RequestPowerState(ctx context.Context, requested PowerState) error {
	status, err := c.Status(ctx)
	if err != nil {
		return err
	}
	// An empty AvailableRequestedPowerStates means the device did not say,
	// not that nothing is permitted, so the pre-check is skipped and
	// RequestPowerStateChange is allowed to report the failure itself.
	if len(status.AvailableRequestedPowerStates) > 0 &&
		!containsState(status.AvailableRequestedPowerStates, requested) {
		return fmt.Errorf("iamt: there is no implemented transition state to <%d> from the current machine state <%d>. available states are: %v",
			requested, status.PowerState, status.AvailableRequestedPowerStates)
	}

	c.Log.V(1).Info("sending request to machine", "PowerState", requested)

	resp, err := c.Msg.CIM.PowerManagementService.RequestPowerStateChange(cimpower.PowerState(requested))
	if err != nil {
		return fmt.Errorf("iamt: requesting power state %d: %w", requested, err)
	}

	rv := resp.Body.RequestPowerStateChangeResponse.ReturnValue
	c.Log.V(1).Info("RequestPowerState response", "response", rv)
	if rv != 0 {
		return fmt.Errorf("iamt: RequestPowerStateChange returned non-zero response: %d", rv)
	}
	return nil
}

// powerOffStates lists power-off transitions from gentlest to harshest.
func powerOffStates() []PowerState {
	return []PowerState{
		PowerOffSoftGraceful,
		PowerOffSoft,
		PowerOffHardGraceful,
		PowerOffHard,
	}
}

// powerCycleStates lists power-cycle transitions from gentlest to harshest.
func powerCycleStates() []PowerState {
	return []PowerState{
		PowerCycleOffSoftGraceful,
		PowerCycleOffSoft,
		PowerMasterBusResetGrace,
		PowerCycleOffHardGraceful,
		PowerCycleOffHard,
		PowerMasterBusReset,
	}
}

// selectState returns the first wanted state the device advertises, or
// PowerUnknown when none match.
func selectState(wanted, available []PowerState) PowerState {
	for _, w := range wanted {
		if containsState(available, w) {
			return w
		}
	}
	return PowerUnknown
}

func containsState(states []PowerState, want PowerState) bool {
	for _, s := range states {
		if s == want {
			return true
		}
	}
	return false
}
