package iamt_test

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/jacobweinstock/iamt"
)

// bmclibClient is the interface bmclib's intelamt provider requires of this
// package, copied verbatim from
// github.com/bmc-toolbox/bmclib/v2/providers/intelamt.
//
// It is asserted here so a refactor cannot quietly break the only downstream
// consumer that matters. The migration from the in-repo WS-Man layer to
// go-wsman-messages changed every implementation behind this interface; the
// interface itself must not move.
type bmclibClient interface {
	Close(context.Context) error
	IsPoweredOn(context.Context) (bool, error)
	Open(context.Context) error
	PowerCycle(context.Context) error
	PowerOff(context.Context) error
	PowerOn(context.Context) error
	SetPXE(context.Context) error
}

var _ bmclibClient = (*iamt.Client)(nil)

// The constructor signature and options bmclib calls must also keep working.
func TestBmclibConstructionCompiles(t *testing.T) {
	t.Parallel()

	// Mirrors intelamt.New: logger, port and scheme options, in that shape.
	c := iamt.NewClient("10.0.0.1", "admin", "hunter2",
		iamt.WithLogger(logr.Discard()),
		iamt.WithPort(16992),
		iamt.WithScheme("http"),
	)
	if c == nil {
		t.Fatal("NewClient returned nil")
	}

	var client bmclibClient = c
	if client == nil {
		t.Fatal("client does not satisfy the bmclib interface")
	}
}
