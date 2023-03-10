// Code generated by "stringer -type=powerState -linecomment -output=power_string.go"; DO NOT EDIT.

package internal

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[unknown-0]
	_ = x[other-1]
	_ = x[stateOn-2]
	_ = x[sleepLight-3]
	_ = x[sleepDeep-4]
	_ = x[powerCycleOffSoft-5]
	_ = x[offHard-6]
	_ = x[hibernateOffSoft-7]
	_ = x[offSoft-8]
	_ = x[powerCycleOffHard-9]
	_ = x[masterBusReset-10]
	_ = x[diagnosticInterruptNMI-11]
	_ = x[offSoftGraceful-12]
	_ = x[offHardGraceful-13]
	_ = x[masterBusResetGraceful-14]
	_ = x[powerCycleOffSoftGraceful-15]
	_ = x[powerCycleOffHardGraceful-16]
	_ = x[diagnosticInterruptInit-17]
}

const _powerState_name = "unknownotherstateOnsleepLightsleepDeeppowerCycleOffSoftoffHardhibernateOffSoftoffSoftpowerCycleOffHardmasterBusResetdiagnosticInterruptNMIoffSoftGracefuloffHardGracefulmasterBusResetGracefulpowerCycleOffSoftGracefulpowerCycleOffHardGracefuldiagnosticInterruptInit"

var _powerState_index = [...]uint16{0, 7, 12, 19, 29, 38, 55, 62, 78, 85, 102, 116, 138, 153, 168, 190, 215, 240, 263}

func (i powerState) String() string {
	if i < 0 || i >= powerState(len(_powerState_index)-1) {
		return "powerState(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _powerState_name[_powerState_index[i]:_powerState_index[i+1]]
}
