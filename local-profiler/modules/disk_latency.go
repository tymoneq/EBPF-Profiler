package modules

import (
	synchronization "local-profiler/synchronization"
)

type IOStats struct {
	ReadBytes  uint64
	WriteBytes uint64
	ReadCount  uint64
	WriteCount uint64
}

func (s IOStats) Add(other IOStats) IOStats {
	return IOStats{
		ReadBytes:  s.ReadBytes + other.ReadBytes,
		WriteBytes: s.WriteBytes + other.WriteBytes,
		ReadCount:  s.ReadCount + other.ReadCount,
		WriteCount: s.WriteCount + other.WriteCount,
	}
}

func (s IOStats) Mul(scalar uint64) IOStats {
	return IOStats{
		ReadBytes:  s.ReadBytes * scalar,
		WriteBytes: s.WriteBytes * scalar,
		ReadCount:  s.ReadCount * scalar,
		WriteCount: s.WriteCount * scalar,
	}
}

func (o BPFObject) GetDiskLatency(sync *synchronization.SyncStruct) error {
	defer sync.Wg.Done()
	profiler := ProfilerStruct{
		SamplePeriod:    1,
		TimeInterval:    5,
		FileName:        "IOReadWrite",
		ProfilerMessage: "I/O profiler started. Collecting data...",
		sync:            sync,
	}

	profilerData := ProfilerData[IOStats]{
		zeroValues: &[]IOStats{},
	}

	return RunGoRoutine(&profiler, o.Objs.ProcessIoStats, profilerData)

}
