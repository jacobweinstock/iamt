# amt

Go client library to interact with the Intel AMT api (via wsman)

**Fork of github.com/ammmze/go-amt**

## Usage

```golang
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/jacobweinstock/iamt"
)

func main() {
	conn := amt.Connection{
		Host: "127.0.0.1",
		User: "admin",
		Pass: "admin",
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := amt.NewClient(ctx, conn)
	if err != nil {
		panic(err)
	}
	on, err := client.IsPoweredOn(ctx)
	if err != nil {
		panic(err)
	}
    fmt.Println("Is powered on?", on)
}
```
