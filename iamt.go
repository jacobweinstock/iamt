package iamt

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-logr/logr"
	"github.com/jacobweinstock/iamt/internal"
	"github.com/jacobweinstock/iamt/wsman"
)

// Client used to perform actions on the machine
type Client struct {
	Host   string
	Port   uint32
	Path   string
	User   string
	Pass   string
	Logger logr.Logger

	connMu sync.Mutex
	conn   internal.Client
}

// NewClient creates an amt client to use.
func NewClient(log logr.Logger, host, path, user, passwd string) *Client {
	if path == "" {
		path = "/wsman"
	}

	logger := logr.Discard()
	if log.GetSink() != nil {
		logger = log
	}

	return &Client{
		Host:   host,
		Port:   16992,
		Path:   path,
		User:   user,
		Pass:   passwd,
		Logger: logger,
		conn:   internal.Client{Log: logger},
	}
}

func (c *Client) Open(ctx context.Context) error {
	// TODO: add support for https
	target := fmt.Sprintf("http://%s:%d%s", c.Host, c.Port, c.Path)
	wsmanClient, err := wsman.NewClient(ctx, c.Logger, target, c.User, c.Pass, true)
	if err != nil {
		return err
	}

	c.connMu.Lock()
	c.conn.WsmanClient = wsmanClient
	c.connMu.Unlock()

	return nil
}

// Close the client.
func (c *Client) Close(_ context.Context) error {
	return nil
}

// PowerOn will power on a given machine.
func (c *Client) PowerOn(ctx context.Context) error {
	return c.conn.PowerOn(ctx)
}

// PowerOff will power off a given machine.
func (c *Client) PowerOff(ctx context.Context) error {
	return c.conn.PowerOff(ctx)
}

// PowerCycle will power cycle a given machine.
func (c *Client) PowerCycle(ctx context.Context) error {
	return c.conn.PowerCycle(ctx)
}

// SetPXE makes sure the node will pxe boot next time.
func (c *Client) SetPXE(ctx context.Context) error {
	return c.conn.SetPXE(ctx)
}

// IsPoweredOn checks current power state.
func (c *Client) IsPoweredOn(ctx context.Context) (bool, error) {
	return c.conn.IsPoweredOn(ctx)
}
