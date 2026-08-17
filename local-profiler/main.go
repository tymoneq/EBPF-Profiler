package main

import (
	"fmt"
	"local-profiler/modules"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

func main() {
	const NUMBER_OF_GO_ROUTINES int32 = 1

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

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
		if err := obj.ContextSwitches(); err != nil {
			errChan <- err
		}
	}()

	go func() {
		obj.GetDiskLatency()
	}()

	select {
	case sig := <-sigChan:
		fmt.Printf("\nReceived OS signal (%s). Shutting down gracefully...\n", sig)

	}

	// Add your cleanup logic here (closing DBs, flushing logs, etc.)
	fmt.Println("Cleanup complete. Goodbye.")

}
