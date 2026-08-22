package modules

import (
	synchronization "local-profiler/synchronization"
)

type PageFaultStruct struct {
	MinorFaults uint64
	MajorFaults uint64
}

func (p PageFaultStruct) Add(other PageFaultStruct) PageFaultStruct {
	return PageFaultStruct{
		MinorFaults: p.MinorFaults + other.MinorFaults,
		MajorFaults: p.MajorFaults + other.MajorFaults,
	}

}

func (p PageFaultStruct) Mul(scalar uint64) PageFaultStruct {
	return PageFaultStruct{
		MinorFaults: p.MinorFaults * scalar,
		MajorFaults: p.MajorFaults * scalar,
	}
}

func (o BPFObject) PageFaults(sync *synchronization.SyncStruct) error {
	defer sync.Wg.Done()

	profiler := ProfilerStruct{
		SamplePeriod:    1,
		TimeInterval:    5,
		FileName:        "pageFaults",
		ProfilerMessage: "RAM Profiler is working, listening for page faults...",
		sync:            sync,
	}

	profilerData := ProfilerData[PageFaultStruct]{
		zeroValues: &[]PageFaultStruct{},
	}

	return RunGoRoutine(&profiler, o.Objs.PageFault, profilerData)

}
