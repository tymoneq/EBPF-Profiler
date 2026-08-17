package modules

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type IOStats struct {
	ReadBytes  uint64
	WriteBytes uint64
	ReadCount  uint64
	WriteCount uint64
}

func (o BPFObject) GetDiskLatency(ctx *context.Context, wg *sync.WaitGroup) error {
	defer wg.Done()

	numCPUs, err := ebpf.PossibleCPU()
	zeroValues := make([]IOStats, numCPUs)

	outFile, err := OpenFile("IOReadWrite.log")
	if err != nil {
		log.Printf("Error opening disk profiler log file : %v\n", err)
		return err
	}
	defer outFile.Close()

	tpIssue, err := link.Kretprobe("vfs_read", o.Objs.VfsReadRet, nil)

	if err != nil {
		log.Fatalf("Error hooking vfs read %v\n", err)
		return err
	}
	defer tpIssue.Close()

	tpComplete, err := link.Kretprobe("vfs_write", o.Objs.VfsWriteRet, nil)

	if err != nil {
		log.Fatalf("Error hooking vfs write: %v\n", err)
		return err
	}
	defer tpComplete.Close()

	fmt.Println("I/O profiler started. Collecting data...")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {

		select {
		case <-(*ctx).Done():
			fmt.Println("Cleaning disk latency")
			return nil

		default:
			t := time.Now()
			t.Format("2006-01-02 15:04:05")

			outFile.WriteString("Data from the Kernel: ")
			outFile.Write([]byte(t.String()))
			outFile.WriteString("\n")
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
					myString := fmt.Sprintf("Data for %d pid : \n Total ReadBytes : %d, Total ReadCount : %d, Total WriteBytes : %d, Total WriteCount %d\n", pid, totalCount.ReadBytes, totalCount.ReadCount, totalCount.WriteBytes, totalCount.WriteCount)
					outFile.WriteString(myString)
				}
				err := o.Objs.ProcessIoStats.Update(pid, zeroValues, ebpf.UpdateAny)
				if err != nil {
					log.Printf("Failed to reset key %d: %v", pid, err)
					return err
				}
			}
		}

	}
	return nil
}
