# amt

Go client library to interact with the Intel AMT api (via wsman)

**Fork of [github.com/ammmze/go-amt](https://github.com/ammmze/go-amt)**

WS-Man messages are built and parsed by
[go-wsman-messages](https://github.com/device-management-toolkit/go-wsman-messages),
Intel's own message library, which covers the full AMT, CIM and IPS class
surface. Transport and authentication are this library's own, for two reasons:

- **Digest authentication.** go-wsman-messages splits the `WWW-Authenticate`
  challenge on `","`, so it silently mis-parses the space-separated headers
  some Intel NUCs emit -- `realm` swallows the rest of the header and `nonce`
  comes back empty, which surfaces as an authentication failure rather than a
  parse error. This library keeps its own hardened parser; see
  `internal/digest`.
- **Port and path.** go-wsman-messages derives the port from whether TLS is in
  use and hardcodes the path, so `WithPort` and `WithPath` would be silently
  ignored.

## Capabilities

| | |
|---|---|
| Power | `PowerOn`, `PowerOff`, `PowerCycle`, `IsPoweredOn`, `Status`, `RequestPowerState` |
| Boot | `SetPXE`, `SetBootOverride`, `ClearBootOverride` |
| Virtual media | `InsertVirtualMedia`, `EjectVirtualMedia` (UEFI HTTPS boot) |
| Inventory | `Inventory` -- chassis, baseboard, BIOS, CPUs, memory, NICs, drives |
| Facts | `Facts` -- control mode, provisioning state, firmware, boot capabilities, redirection |
| Credentials | `GeneratePassword`, `ValidatePassword`, `SetAdminPassword` |
| TLS | `Fingerprint`, `WithPinnedCert` |

Boot overrides are one-shot only. AMT clears the boot parameters once they are
consumed, so a persistent override cannot be expressed.

Virtual media uses AMT's One Click Recovery UEFI HTTPS boot: the device fetches
the image itself, so the URL must be reachable from the device and served with
a certificate it trusts. IDE redirection is deliberately not offered -- AMT 11
and later use USB-R rather than IDE-R, the redirection data plane is
undocumented, and it would require holding a session open for the whole boot.

## Usage

```golang
package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "time"

    "github.com/go-logr/logr"
    "github.com/go-logr/stdr"
    "github.com/jacobweinstock/iamt"
)

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
    defer cancel()

    client := iamt.NewClient("127.0.0.1", "admin", "admin", iamt.WithLogger(defaultLogger(0)))
    if err := client.Open(ctx); err != nil {
        panic(err)
    }
    defer client.Close(ctx)
    on, err := client.IsPoweredOn(ctx)
    if err != nil {
        panic(err)
    }
    fmt.Println("Is powered on?", on)
}

func defaultLogger(level int) logr.Logger {
    stdr.SetVerbosity(level)

    return stdr.NewWithOptions(log.New(os.Stderr, "", log.LstdFlags), stdr.Options{LogCaller: stdr.All})
}
```

### Over TLS, with a pinned certificate

AMT ships a self-signed certificate that no chain can validate, so pinning is
what makes a TLS connection trustworthy rather than merely encrypted. Learn the
fingerprint once, then pin it:

```golang
c := iamt.NewClient(host, user, pass, iamt.WithScheme("https"), iamt.WithPort(16993))

fingerprint, err := c.Fingerprint(ctx)
if err != nil {
    panic(err)
}

pinned := iamt.NewClient(host, user, pass,
    iamt.WithScheme("https"),
    iamt.WithPort(16993),
    iamt.WithPinnedCert(fingerprint),
)
```

## Testing

`go test ./...` is hermetic. Integration tests run against a real device when
`AMT_HOST` is set and are read-only:

```sh
AMT_HOST=10.0.0.10 AMT_USER=admin AMT_PASS=... AMT_SCHEME=https AMT_PORT=16993 \
  go test . -run Integration -v
```
