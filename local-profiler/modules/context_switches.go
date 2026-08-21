package modules

import (
	synchronization "local-profiler/synchronization"
)

func (o BPFObject) ContextSwitches(sync *synchronization.SyncStruct) error {
	defer sync.Wg.Done()
	zeroValues := make([]uint64, o.NumCPUs)

	profiler := ProfilerStruct{
		SamplePeriod:    1,
		TimeInterval:    1,
		FileName:        "contexSwitches",
		ProfilerMessage: "CPU Profiler is working, listening for context switches...",
		sync:            sync,
	}

	return RunGoRoutine(&profiler, o.Objs.SwitchCounts, &zeroValues)
}
