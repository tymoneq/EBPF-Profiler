package main

import (
	"context"
	"fmt"
	"local-profiler/modules"
	"log"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

func main() {
	const NUMBER_OF_GO_ROUTINES int32 = 2

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	defer stop()
	var wg sync.WaitGroup
	wg.Add(int(NUMBER_OF_GO_ROUTINES))

	errChan := make(chan error, NUMBER_OF_GO_ROUTINES)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Error with memory limits %v\n", err)
	}

	var obj modules.BPFObject
	if err := modules.LoadBPFObjects(&obj.Objs); err != nil {
		log.Fatalf("Couldn't load eBPF objects : %v \n", err)
	}
	defer obj.Objs.Close()

	go func() {
		if err := obj.ContextSwitches(&ctx, &wg); err != nil {
			errChan <- err
		}
	}()

	go func() {
		if err := obj.GetDiskLatency(&ctx, &wg); err != nil {
			errChan <- err
		}
	}()

	<-ctx.Done()
	fmt.Println("\nMain: Shutdown signal received. Waiting for goroutines to save files...")

	wg.Wait()
	fmt.Println("Cleanup complete. Goodbye.")

}
