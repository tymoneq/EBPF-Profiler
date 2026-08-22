package modules

import (
	"fmt"
	synchronization "local-profiler/synchronization"
	"log"

	"golang.org/x/sys/unix"
)

const SAMPLE_PERIOD = 10_000

func (o BPFObject) createPerfEvents(perfFDs *[]int) error {

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
		*perfFDs = append(*perfFDs, fd)
	}

	if len(*perfFDs) == 0 {
		return fmt.Errorf("Couldn't hook PMU to any core\n")
	}

	return nil
}

func (o BPFObject) CacheMisses(sync *synchronization.SyncStruct) error {
	defer sync.Wg.Done()

	var perfFDs []int

	defer func() {
		for _, fd := range perfFDs {
			unix.Close(fd)
		}
	}()

	if err := o.createPerfEvents(&perfFDs); err != nil {
		return err
	}

	profiler := ProfilerStruct{
		SamplePeriod:    SAMPLE_PERIOD,
		TimeInterval:    5,
		FileName:        "cacheMisses",
		ProfilerMessage: "CPU Profiler is working, listening for cache misses...",
		sync:            sync,
	}
	profilerData := ProfilerData[ProfilerUint]{
		zeroValues: &[]ProfilerUint{},
	}

	return RunGoRoutine(&profiler, o.Objs.CacheMisses, profilerData)
	//			prometheusserver.SaveMetrics(strconv.Itoa(int(pid)), int64(totalCount))

}
