package modules

import (
	"fmt"
	"log"
	"math"
	"time"

	"github.com/cilium/ebpf/link"
)

func (o BPFObject) GetDiskLatency() {
	tpIssue, err := link.AttachTracing(link.TracingOptions{Program: o.Objs.HandleBlockRqIssue})

	if err != nil {
		log.Fatalf("Error hooking rq_issue %v\n", err)
	}
	defer tpIssue.Close()

	tpComplete, err := link.AttachTracing(link.TracingOptions{Program: o.Objs.HandleBlockRqComplete})

	if err != nil {
		log.Fatalf("Error hooking rq_complete: %v\n", err)
	}
	defer tpComplete.Close()

	fmt.Println("I/O profiler started. Collecting data...")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		fmt.Println("\n-----Histogram of delays ------")
		var slot uint32
		var perCPUValues []uint64

		iter := o.Objs.IoHistogram.Iterate()
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
