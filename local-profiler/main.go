package main

import (
	"fmt"
	"log"
	"math"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Magiczna komenda, która łączy C z Go. Kompiluje kod pod architekturę x86_64.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf profiler.bpf.c

func main() {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Error with memory limits %v\n", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Couldn't load eBPF objects : %v \n", err)
	}
	defer objs.Close()

	//tp, err := link.Tracepoint("sched", "sched_switch", objs.HandleSchedSwitch, nil)
	//if err != nil {
	//	log.Fatalf("Couldn't pin tracepoint: %v \n", err)
	//}
	//defer tp.Close()

	//fmt.Println("CPU Profiler is working, listening for context switches...")

	//ticker := time.NewTicker(2 * time.Second)
	//defer ticker.Stop()

	//for range ticker.C {
	//	var pid uint32
	//	var count uint64
	//	var iter = objs.SwitchCounts.Iterate()

	//	fmt.Println("---Active processes (Top context switches)---")

	//	for iter.Next(&pid, &count) {
	//		if count > 50 {
	//			fmt.Printf("PID: %d | Number of context switches: %d\n", pid, count)
	//		}
	//	}

	//}

	tpIssue, err := link.AttachTracing(link.TracingOptions{Program: objs.HandleBlockRqIssue})

	if err != nil {
		log.Fatalf("Error hooking rq_issue %v\n", err)
	}
	defer tpIssue.Close()

	tpComplete, err := link.AttachTracing(link.TracingOptions{Program: objs.HandleBlockRqComplete})

	if err != nil {
		log.Fatalf("Error hooking rq_complete: %v\n", err)
	}
	defer tpComplete.Close()

	fmt.Println("I/O profiler started. Collecting data...")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		fmt.Println("\n-----Histogram of delays ------")
		var slot uint32
		var perCPUValues []uint64

		iter := objs.IoHistogram.Iterate()
		for iter.Next(&slot, &perCPUValues) {

			var totalCount uint64 = 0
			for _, coreCount := range perCPUValues {
				totalCount += coreCount
			}
			if totalCount > 0 {
				lowerBound := uint64(0)
				if slot > 0 {
					lowerBound = uint64(math.Pow(2, float64(slot-1)))
				}
				upperBound := uint64(math.Pow(2, float64(slot)))
				fmt.Printf("[%6d us - %6d us] : %d operacji I/O\n", lowerBound, upperBound, totalCount)
			}

		}

	}
}
