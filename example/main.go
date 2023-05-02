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
