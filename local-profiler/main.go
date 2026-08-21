package main

import (
	"context"
	"fmt"
	"local-profiler/modules"
	prometheusserver "local-profiler/prometheus-server"
	"log"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

const NUMBER_OF_GO_ROUTINES int32 = 6

func createSignalHandling() (*modules.SyncStruct, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup
	wg.Add(int(NUMBER_OF_GO_ROUTINES))

	sync := &modules.SyncStruct{
		Ctx: ctx,
		Wg:  &wg,
	}

	return sync, stop
}

func runServer(sync *modules.SyncStruct, errChan chan<- error) {

	go func() {
		if err := prometheusserver.ConnectToPrometheus(sync); err != nil {
			errChan <- err
		}
	}()
}

func runGoRoutines(obj modules.BPFObject, sync *modules.SyncStruct, errChan chan<- error) {

	go func() {
		if err := obj.ContextSwitches(sync); err != nil {
			errChan <- err
		}
	}()

	go func() {
		if err := obj.GetDiskLatency(sync); err != nil {
			errChan <- err
		}
	}()

	go func() {
		if err := obj.RunqLatency(sync); err != nil {
			errChan <- err
		}
	}()
	go func() {
		if err := obj.CacheMisses(sync); err != nil {
			errChan <- err
		}
	}()
	go func() {
		if err := obj.PageFaults(sync); err != nil {
			errChan <- err
		}
	}()
}

func main() {

	errChan := make(chan error, NUMBER_OF_GO_ROUTINES)

	sync, stop := createSignalHandling()
	defer stop()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Error with memory limits %v\n", err)
	}

	var obj modules.BPFObject
	obj.NumCPUs = runtime.NumCPU()

	if err := modules.LoadBPFObjects(&obj.Objs); err != nil {
		log.Fatalf("Couldn't load eBPF objects : %v \n", err)
	}
	defer obj.Objs.Close()

	arr, err := obj.LoadAllTracepoints()
	if err != nil {
		return
	}

	defer func() {
		for _, l := range arr {
			l.Close()
		}
	}()

	runServer(sync, errChan)
	runGoRoutines(obj, sync, errChan)

	fmt.Println("Enter ctrl-c to stop profiler\n")
	select {
	case <-sync.Ctx.Done():
		fmt.Println("\nMain: Shutdown signal received. Waiting for goroutines to save files...")

	case err := <-errChan:
		fmt.Printf("\nMain: Error in the profiler %v\n", err)
		stop()
	}
	sync.Wg.Wait()

	fmt.Println("Cleanup complete. Goodbye.")

}
