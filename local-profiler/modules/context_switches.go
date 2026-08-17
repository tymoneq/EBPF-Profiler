package modules

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
)

func (o BPFObject) ContextSwitches() error {

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
		var count uint64
		var iter = o.Objs.SwitchCounts.Iterate()

		fmt.Println("---Active processes (Top context switches)---")

		for iter.Next(&pid, &count) {
			if count > 50 {
				fmt.Printf("PID: %d | Number of context switches: %d\n", pid, count)
			}
		}

	}
	return nil
}
