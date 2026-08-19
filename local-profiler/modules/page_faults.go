package modules

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
)

type PageFaultStruct struct {
	MinorFaults uint64
	MajorFaults uint64
}

func (o BPFObject) PageFaults(sync *SyncStruct) error {
	defer sync.Wg.Done()

	outFile, err := OpenFile("pageFaults.log")
	if err != nil {
		log.Printf("Error opening a file : %v\n", err)
		return err
	}
	defer outFile.Close()

	zeroValues := make([]PageFaultStruct, o.NumCPUs)

	fmt.Println("RAM Profiler is working, listening for page faults...")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sync.Ctx.Done():
			fmt.Println("closing page faults")
			return nil

		case t := <-ticker.C:
			t = time.Now()
			t.Format("2006-01-02 15:04:05")

			outFile.WriteString("---Active processes (Top page faults)---")
			outFile.Write([]byte(t.String()))
			outFile.WriteString("\n")

			var pid uint32
			var perCpuCount []PageFaultStruct
			var iter = o.Objs.PageFault.Iterate()

			for iter.Next(&pid, &perCpuCount) {
				userName := getUserForPID(pid)

				var totalCount PageFaultStruct = PageFaultStruct{0, 0}
				for _, coreCount := range perCpuCount {
					totalCount.MajorFaults += coreCount.MajorFaults
					totalCount.MinorFaults += coreCount.MinorFaults
				}
				if totalCount.MajorFaults > 0 || totalCount.MinorFaults > 0 {
					myString := fmt.Sprintf("PID: %d , UserName : %s | Number of minor page faults: %d | Number of major page faults: %d \n", pid, userName, totalCount.MinorFaults, totalCount.MajorFaults)
					outFile.WriteString(myString)
				}

				err := o.Objs.PageFault.Update(pid, zeroValues, ebpf.UpdateAny)
				if err != nil {
					log.Printf("Failed to reset key %d: %v", pid, err)
					return err
				}
			}
		}

	}
}
