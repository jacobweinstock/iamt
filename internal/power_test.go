package internal

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
)

func TestSelectNextState_When_NoneOfTheRequestedStatesAreAvailable_Expect_Unknown(t *testing.T) {
	availableStates := []powerState{stateOn}
	nextState := selectNextState(getPowerOffStates(), availableStates)
	assert.Equal(t, unknown, nextState)
}

func TestSelectNextState_When_OneOfTheRequestedStatesAreAvailable_Expect_RequestedState(t *testing.T) {
	requestedStates := getPowerOffStates()
	availableStates := []powerState{requestedStates[0]}
	nextState := selectNextState(requestedStates, availableStates)
	assert.Equal(t, requestedStates[0], nextState)
}

func TestSelectNextState_When_MultipleOfTheRequestedStatesAreAvailable_Expect_FirstAvailableRequestedState(t *testing.T) {
	requestedStates := getPowerOffStates()
	availableStates := []powerState{requestedStates[1], requestedStates[2]}
	nextState := selectNextState(requestedStates, availableStates)
	assert.Equal(t, requestedStates[1], nextState)
}

func TestIsPoweredOnGivenStatus_When_powerStateOn_Expect_True(t *testing.T) {
	status := &powerStatus{powerState: stateOn}
	actual := isPoweredOnGivenStatus(logr.Discard(), status)
	assert.Equal(t, true, actual)
}

func TestIsPoweredOnGivenStatus_When_powerStateOffSoft_Expect_False(t *testing.T) {
	status := &powerStatus{powerState: offSoft}
	actual := isPoweredOnGivenStatus(logr.Discard(), status)
	assert.Equal(t, false, actual)
}
