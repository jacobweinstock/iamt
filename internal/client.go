// Package internal implements the Intel AMT operations exposed by the parent
// iamt package.
//
// It is internal for the same reason it always was: the public surface is the
// thin facade in iamt.go, and everything here is free to change. WS-Man
// messages are built and parsed by go-wsman-messages; transport and
// authentication live in internal/digest.
package internal

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/jacobweinstock/iamt/internal/digest"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman"
)

// Client is a connection to one AMT device.
type Client struct {
	Log logr.Logger

	// Msg builds and sends WS-Man messages.
	Msg wsman.Messages

	// Transport owns authentication and the port and path overrides.
	Transport *digest.Transport

	// Endpoint is the WS-Man URL, used by Open to probe for a challenge.
	Endpoint string
}

// Open confirms the endpoint is an AMT WS-Man service by requiring a digest
// challenge, and caches that challenge so later calls skip a round trip.
//
// It deliberately does not verify credentials. That matches the previous
// implementation, and callers such as bmclib use Open only to decide whether
// the AMT provider applies to a host.
func (c *Client) Open(ctx context.Context) error {
	return c.Transport.Prime(ctx, c.Endpoint)
}

// Close discards the cached challenge.
func (c *Client) Close(_ context.Context) error {
	c.Transport.Reset()
	return nil
}
