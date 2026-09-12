package internal

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Inventory is the hardware inventory read from a device's CIM classes.
//
// The types are this package's own rather than bmc-toolbox/common: an AMT
// library should not require its callers to adopt one BMC ecosystem's model.
// Mapping to common.Device, redfish, or anything else is a few lines in the
// caller.
type Inventory struct {
	Manufacturer string
	Model        string
	SerialNumber string

	Baseboard Baseboard
	BIOS      BIOS
	CPUs      []CPU
	Memory    []MemoryModule
	NICs      []NIC
	Drives    []Drive
}

// MemoryBytes is the total installed memory.
func (i Inventory) MemoryBytes() int64 {
	var total int64
	for _, m := range i.Memory {
		total += m.CapacityBytes
	}
	return total
}

// Baseboard is the system board.
type Baseboard struct {
	Manufacturer string
	Model        string
	SerialNumber string
	Version      string
}

// BIOS is the system firmware.
type BIOS struct {
	Vendor      string
	Version     string
	ReleaseDate string
}

// CPU is one processor package.
type CPU struct {
	ID              string
	Name            string
	MaxClockMHz     int
	CurrentClockMHz int
	Family          int
	Stepping        string
}

// MemoryModule is one installed DIMM.
type MemoryModule struct {
	BankLabel     string
	Manufacturer  string
	PartNumber    string
	SerialNumber  string
	CapacityBytes int64
	ClockMHz      int
}

// NIC is one host network interface.
type NIC struct {
	MACAddress string
	Name       string
}

// Drive is one storage device.
//
// AMT splits a drive across two classes: CIM_MediaAccessDevice carries the
// identifier and capacity, while the model and serial live on the matching
// CIM_PhysicalPackage. Reading only the former -- which the element name
// invites, since it is the constant "Managed System Media Access Device" on
// every drive -- yields a capacity and nothing to attach it to.
type Drive struct {
	// ID is the device identifier, e.g. "MEDIA DEV 0".
	ID string
	// MaxMediaSizeKB is the capacity as reported by CIM, in kilobytes. Zero
	// when the device does not report it.
	MaxMediaSizeKB uint64
	// Model is the drive's model, e.g. "Lexar SSD NM790 2TB". Empty when no
	// storage package matches the device.
	Model string
	// SerialNumber is the drive's serial. Empty on the same terms as Model.
	SerialNumber string
}

// Inventory reads the device's hardware inventory.
//
// Every class is read independently and a failure in one is tolerated: AMT
// populates these unevenly across platforms and firmware versions, and a
// partial inventory is materially more useful than none. Only a failure to
// read the chassis -- which carries the identifying model and serial -- is
// reported as an error.
func (c *Client) Inventory(ctx context.Context) (*Inventory, error) {
	chassis, err := c.chassis(ctx)
	if err != nil {
		return nil, err
	}

	inv := &Inventory{
		Manufacturer: chassis.Manufacturer,
		Model:        chassis.Model,
		SerialNumber: chassis.SerialNumber,
		Baseboard:    c.baseboard(ctx),
		BIOS:         c.bios(ctx),
		CPUs:         c.cpus(ctx),
		Memory:       c.memory(ctx),
		NICs:         c.nics(ctx),
		Drives:       c.drives(ctx),
	}
	return inv, nil
}

type chassisInfo struct {
	Manufacturer string
	Model        string
	SerialNumber string
}

func (c *Client) chassis(_ context.Context) (chassisInfo, error) {
	enum, err := c.Msg.CIM.Chassis.Enumerate()
	if err != nil {
		return chassisInfo{}, fmt.Errorf("iamt: enumerating chassis: %w", err)
	}
	pull, err := c.Msg.CIM.Chassis.Pull(enum.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return chassisInfo{}, fmt.Errorf("iamt: reading chassis: %w", err)
	}
	items := pull.Body.PullResponse.PackageItems
	if len(items) == 0 {
		return chassisInfo{}, fmt.Errorf("iamt: device reported no chassis")
	}
	return chassisInfo{
		Manufacturer: strings.TrimSpace(items[0].Manufacturer),
		Model:        strings.TrimSpace(items[0].Model),
		SerialNumber: strings.TrimSpace(items[0].SerialNumber),
	}, nil
}

func (c *Client) baseboard(_ context.Context) Baseboard {
	enum, err := c.Msg.CIM.Card.Enumerate()
	if err != nil {
		return Baseboard{}
	}
	pull, err := c.Msg.CIM.Card.Pull(enum.Body.EnumerateResponse.EnumerationContext)
	if err != nil || len(pull.Body.PullResponse.CardItems) == 0 {
		return Baseboard{}
	}
	card := pull.Body.PullResponse.CardItems[0]
	return Baseboard{
		Manufacturer: strings.TrimSpace(card.Manufacturer),
		Model:        strings.TrimSpace(card.Model),
		SerialNumber: strings.TrimSpace(card.SerialNumber),
		Version:      strings.TrimSpace(card.Version),
	}
}

func (c *Client) bios(_ context.Context) BIOS {
	resp, err := c.Msg.CIM.BIOSElement.Get()
	if err != nil {
		return BIOS{}
	}
	b := resp.Body.BIOSElementGetResponse
	return BIOS{
		Vendor:      strings.TrimSpace(b.Manufacturer),
		Version:     strings.TrimSpace(b.Version),
		ReleaseDate: b.ReleaseDate.DateTime,
	}
}

func (c *Client) cpus(_ context.Context) []CPU {
	enum, err := c.Msg.CIM.Processor.Enumerate()
	if err != nil {
		return nil
	}
	pull, err := c.Msg.CIM.Processor.Pull(enum.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil
	}

	out := make([]CPU, 0, len(pull.Body.PullResponse.PackageItems))
	for _, p := range pull.Body.PullResponse.PackageItems {
		out = append(out, CPU{
			ID:              strings.TrimSpace(p.DeviceID),
			Name:            strings.TrimSpace(p.ElementName),
			MaxClockMHz:     p.MaxClockSpeed,
			CurrentClockMHz: p.CurrentClockSpeed,
			Family:          p.Family,
			Stepping:        strings.TrimSpace(p.Stepping),
		})
	}
	return out
}

func (c *Client) memory(_ context.Context) []MemoryModule {
	enum, err := c.Msg.CIM.PhysicalMemory.Enumerate()
	if err != nil {
		return nil
	}
	pull, err := c.Msg.CIM.PhysicalMemory.Pull(enum.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil
	}

	var out []MemoryModule
	for _, m := range pull.Body.PullResponse.MemoryItems {
		if m.Capacity == 0 {
			continue
		}
		out = append(out, MemoryModule{
			BankLabel:     strings.TrimSpace(m.BankLabel),
			Manufacturer:  strings.TrimSpace(m.Manufacturer),
			PartNumber:    strings.TrimSpace(m.PartNumber),
			SerialNumber:  strings.TrimSpace(m.SerialNumber),
			CapacityBytes: int64(m.Capacity),
			ClockMHz:      m.ConfiguredMemoryClockSpeed,
		})
	}
	return out
}

// nics reads CIM_EthernetPort.
//
// The MAC is not where CIM says it should be: AMT leaves PermanentAddress
// empty and reports the address in NetworkAddresses instead, without
// separators. Both are checked, and the result is normalised to the
// colon-separated lower-case form.
func (c *Client) nics(_ context.Context) []NIC {
	enum, err := c.Msg.CIM.EthernetPort.Enumerate()
	if err != nil {
		return nil
	}
	pull, err := c.Msg.CIM.EthernetPort.Pull(enum.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil
	}

	var out []NIC
	for _, p := range pull.Body.PullResponse.EthernetPortItems {
		mac := NormalizeMAC(p.PermanentAddress)
		for _, addr := range p.NetworkAddresses {
			if mac != "" {
				break
			}
			mac = NormalizeMAC(addr)
		}
		// An unpopulated port -- a disabled wireless radio, typically --
		// reports an all-zero address. Surfacing it would put a bogus
		// interface on every device that has one, all of them identical.
		if mac == "" || isZeroMAC(mac) {
			continue
		}
		name := strings.TrimSpace(p.Description)
		if name == "" {
			name = strings.TrimSpace(p.ElementName)
		}
		out = append(out, NIC{MACAddress: mac, Name: name})
	}
	return out
}

func (c *Client) drives(_ context.Context) []Drive {
	enum, err := c.Msg.CIM.MediaAccessDevice.Enumerate()
	if err != nil {
		return nil
	}
	pull, err := c.Msg.CIM.MediaAccessDevice.Pull(enum.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil
	}

	packages := c.storagePackages()

	var out []Drive
	for _, d := range pull.Body.PullResponse.MediaAccessDevices {
		id := strings.TrimSpace(d.DeviceID)
		if id == "" {
			continue
		}
		drive := Drive{ID: id, MaxMediaSizeKB: d.MaxMediaSize}
		if pkg, ok := packages[trailingOrdinal(id)]; ok {
			drive.Model = pkg.Model
			drive.SerialNumber = pkg.SerialNumber
		}
		out = append(out, drive)
	}
	return out
}

// storagePackage is the model and serial of one CIM_PhysicalPackage that
// describes a drive.
type storagePackage struct {
	Model        string
	SerialNumber string
}

// storagePackageType is the CIM PackageType for "Storage Media Package (e.g.
// Disk or Tape Drive)". CIM_PhysicalPackage also enumerates the chassis and
// baseboard, which must not be mistaken for drives.
const storagePackageType = 15

// storagePackages reads the drive-describing CIM_PhysicalPackage instances,
// keyed by the ordinal that ties them back to a CIM_MediaAccessDevice.
//
// "MEDIA DEV 0" is described by "Storage Media Package 0", and the ordinal is
// what ties them together here. Parsing it from both sides, rather than
// assuming the two enumerations arrive in the same order, means a device with
// no counterpart keeps an empty model and serial instead of borrowing another
// drive's identity.
//
// AMT does also publish the authoritative CIM_Realizes association for these
// (verified on a NUC15CRHV7: PhysicalPackage "Storage Media Package 0" ->
// MediaAccessDevice "MEDIA DEV 0"). Using it would remove the dependency on
// the tags being named in parallel, at the cost of a third round trip and
// hand-rolled WS-Man -- go-wsman-messages exposes no CIM_Realizes class.
func (c *Client) storagePackages() map[int]storagePackage {
	enum, err := c.Msg.CIM.PhysicalPackage.Enumerate()
	if err != nil {
		return nil
	}
	pull, err := c.Msg.CIM.PhysicalPackage.Pull(enum.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil
	}

	out := map[int]storagePackage{}
	for _, p := range pull.Body.PullResponse.PhysicalPackage {
		if p.PackageType != storagePackageType {
			continue
		}
		ordinal := trailingOrdinal(p.Tag)
		if ordinal < 0 {
			continue
		}
		// AMT pads these to a fixed width.
		out[ordinal] = storagePackage{
			Model:        strings.TrimSpace(p.Model),
			SerialNumber: strings.TrimSpace(p.SerialNumber),
		}
	}
	return out
}

// trailingOrdinal returns the integer at the end of s ("MEDIA DEV 10" -> 10),
// or -1 if it does not end in one. A missing ordinal must not collide with a
// real index, so it cannot default to zero.
func trailingOrdinal(s string) int {
	s = strings.TrimSpace(s)
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	if i == len(s) {
		return -1
	}
	n, err := strconv.Atoi(s[i:])
	if err != nil {
		return -1
	}
	return n
}

// isZeroMAC reports whether a normalised MAC is all zeroes.
func isZeroMAC(mac string) bool { return mac == "00:00:00:00:00:00" }

// NormalizeMAC renders a MAC address as lower-case colon-separated octets.
// It accepts the bare 12-hex-digit form AMT reports as well as addresses that
// already carry ':' or '-' separators, and returns "" for anything else.
func NormalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(":", "", "-", "", ".", "").Replace(s)
	if len(s) != 12 {
		return ""
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ""
		}
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(s[i : i+2])
	}
	return b.String()
}
