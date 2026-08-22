package modules

import (
	synchronization "local-profiler/synchronization"
)

func (o BPFObject) ContextSwitches(sync *synchronization.SyncStruct) error {
	defer sync.Wg.Done()
	profiler := ProfilerStruct{
		SamplePeriod:    1,
		TimeInterval:    1,
		FileName:        "contexSwitches",
		ProfilerMessage: "CPU Profiler is working, listening for context switches...",
		sync:            sync,
	}

	profilerData := ProfilerData[ProfilerUint]{
		zeroValues: &[]ProfilerUint{},
		data:       &[]ProfilerUint{},
	}

	return RunGoRoutine(&profiler, o.Objs.SwitchCounts, profilerData)
}
