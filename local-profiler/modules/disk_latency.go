package modules

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
)

type IOStats struct {
	ReadBytes  uint64
	WriteBytes uint64
	ReadCount  uint64
	WriteCount uint64
}

func (o BPFObject) GetDiskLatency() {

	tpIssue, err := link.Kretprobe("vfs_read", o.Objs.VfsReadRet, nil)

	if err != nil {
		log.Fatalf("Error hooking vfs read %v\n", err)
	}
	defer tpIssue.Close()

	tpComplete, err := link.Kretprobe("vfs_write", o.Objs.VfsWriteRet, nil)

	if err != nil {
		log.Fatalf("Error hooking vfs write: %v\n", err)
	}
	defer tpComplete.Close()

	fmt.Println("I/O profiler started. Collecting data...")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		fmt.Println("\n-----Histogram of delays ------")
		var pid uint32
		var perCPUValues []IOStats

		iter := o.Objs.ProcessIoStats.Iterate()
		for iter.Next(&pid, &perCPUValues) {
			var totalCount IOStats
			for _, val := range perCPUValues {
				totalCount.ReadBytes += val.ReadBytes
				totalCount.ReadCount += val.ReadCount
				totalCount.WriteBytes += val.WriteBytes
				totalCount.WriteCount += val.WriteCount
			}
			if totalCount.ReadBytes > 0 || totalCount.WriteBytes > 0 {
				fmt.Printf("Data for %d pid : \n Total ReadBytes : %d, Total ReadCount : %d, Total WriteBytes : %d, Total WriteCount %d\n", pid, totalCount.ReadBytes, totalCount.ReadCount, totalCount.WriteBytes, totalCount.WriteCount)
			}
		}

	}
}
