package modules

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
)

func (o BPFObject) ContextSwitches(sync *SyncStruct) error {
	defer sync.Wg.Done()

	outFile, err := OpenFile("contexStiches.log")
	if err != nil {
		log.Printf("Error opening a file : %v\n", err)
		return err
	}
	defer outFile.Close()

	zeroValues := make([]uint64, o.NumCPUs)

	fmt.Println("CPU Profiler is working, listening for context switches...")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sync.Ctx.Done():
			fmt.Println("closing context switches")
			return nil

		case t := <-ticker.C:
			t = time.Now()
			t.Format("2006-01-02 15:04:05")

			outFile.WriteString("---Active processes (Top context switches)---")
			outFile.Write([]byte(t.String()))
			outFile.WriteString("\n")

			var pid uint32
			var perCpuCount []uint64
			var iter = o.Objs.SwitchCounts.Iterate()

			for iter.Next(&pid, &perCpuCount) {
				userName := getUserForPID(pid)

				var totalCount uint64 = 0
				for _, coreCount := range perCpuCount {
					totalCount += coreCount
				}
				if totalCount > 0 {
					myString := fmt.Sprintf("PID: %d , UserName : %s | Number of context switches: %d\n", pid, userName, totalCount)
					outFile.WriteString(myString)
				}

				err := o.Objs.SwitchCounts.Update(pid, zeroValues, ebpf.UpdateAny)
				if err != nil {
					log.Printf("Failed to reset key %d: %v", pid, err)
					return err
				}
			}
		}

	}
}
