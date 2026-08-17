package modules

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func (o BPFObject) ContextSwitches() error {
	numCPUs, err := ebpf.PossibleCPU()
	zeroValues := make([]uint64, numCPUs)

	tp, err := link.Tracepoint("sched", "sched_switch", o.Objs.HandleSchedSwitch, nil)
	if err != nil {
		fmt.Printf("Couldn't pin tracepoint: %v \n", err)
		return err
	}
	defer tp.Close()

	fmt.Println("CPU Profiler is working, listening for context switches...")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var pid uint32
		var perCpuCount []uint64
		var iter = o.Objs.SwitchCounts.Iterate()

		fmt.Println("---Active processes (Top context switches)---")

		for iter.Next(&pid, &perCpuCount) {

			var totalCount uint64 = 0
			for _, coreCount := range perCpuCount {
				totalCount += coreCount
			}

			if totalCount > 0 {
				fmt.Printf("PID: %d | Number of context switches: %d\n", pid, totalCount)
			}

			err := o.Objs.SwitchCounts.Update(pid, zeroValues, ebpf.UpdateAny)
			if err != nil {
				log.Printf("Failed to reset key %d: %v", pid, err)
				return err
			}
		}

	}
	return nil
}
