package modules

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const SAMPLE_PERIOD = 10_000

func (o BPFObject) CacheMisses(sync *SyncStruct) error {
	defer sync.Wg.Done()
	zeroValues := make([]uint64, o.NumCPUs)

	outFile, err := OpenFile("cacheMisses.log")
	if err != nil {
		log.Printf("Error opening a file : %v\n", err)
		return err
	}
	defer outFile.Close()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var perfFDs []int

	defer func() {
		for _, fd := range perfFDs {
			unix.Close(fd)
		}
	}()

	for cpu := 0; cpu < o.NumCPUs; cpu++ {
		attr := unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_HARDWARE,
			Config: unix.PERF_COUNT_HW_CACHE_MISSES,
			Sample: SAMPLE_PERIOD,
		}

		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, 0)
		if err != nil {
			log.Printf("[!] WARNING: SKIPPED CPU %d (NO ACCESS TO PMU): %v\n", cpu, err)
			continue
		}
		err = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, o.Objs.HandleCacheMisses.FD())
		if err != nil {
			log.Printf("Error hooking eBPF to the counter: %v\n", err)
			continue
		}
		err = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0)
		if err != nil {
			log.Printf("Error ioctl Enable : %v\n", err)
			continue
		}
		perfFDs = append(perfFDs, fd)
	}

	if len(perfFDs) == 0 {
		return fmt.Errorf("Couldn't hook PMU to any core\n")
	}

	fmt.Println("CPU Profiler is working, listening for cache misses...")

	for {

		select {
		case <-sync.Ctx.Done():
			fmt.Println("closing cache misses")
			return nil

		case t := <-ticker.C:

			t = time.Now()
			t.Format("2006-01-02 15:04:05")

			outFile.WriteString("---Cache misses---\n")
			outFile.WriteString(t.Format("2006-01-02 15:04:05") + "\n")

			var pid uint32
			var sampleCount []uint64
			var iter = o.Objs.CacheMisses.Iterate()

			for iter.Next(&pid, &sampleCount) {
				userName := getUserForPID(pid)

				var totalCount uint64 = 0
				for _, coreCount := range sampleCount {
					totalCount += coreCount
				}

				totalCount *= SAMPLE_PERIOD
				myString := fmt.Sprintf("PID : %d USERNAME : %s , number of cache misses: %d\n", pid, userName, totalCount)

				outFile.WriteString(myString)

				err := o.Objs.CacheMisses.Update(pid, zeroValues, ebpf.UpdateAny)
				if err != nil {
					log.Printf("Failed to reset key %d: %v", pid, err)
					return err
				}
			}
		}
	}
}
