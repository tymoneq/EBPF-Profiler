package modules

import (
	"fmt"
	synchronization "local-profiler/synchronization"
	"log"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
)

type ProfilerStruct struct {
	SamplePeriod    uint64
	TimeInterval    int
	FileName        string
	ProfilerMessage string
	sync            *synchronization.SyncStruct
}

func RunGoRoutine(profiler *ProfilerStruct, hook *ebpf.Map, zeroValues *[]uint64) error {

	outFile, err := OpenFile(profiler.FileName + ".log")
	if err != nil {
		log.Printf("Error opening a file : %v\n", err)
		return err
	}
	defer outFile.Close()

	ticker := time.NewTicker(time.Duration(profiler.TimeInterval) * time.Second)
	defer ticker.Stop()

	fmt.Printf("%s\n", profiler.ProfilerMessage)

	for {

		select {
		case <-profiler.sync.Ctx.Done():
			fmt.Printf("closing %s\n", profiler.FileName)
			return nil

		case t := <-ticker.C:

			t = time.Now()
			t.Format("2006-01-02 15:04:05")

			outString := fmt.Sprintf("---%s---\n", profiler.FileName)
			outFile.WriteString(outString)
			outFile.WriteString(t.Format("2006-01-02 15:04:05") + "\n")

			var pid uint32
			var sampleCount []uint64
			var iter = hook.Iterate()

			for iter.Next(&pid, &sampleCount) {
				userName := getUserForPID(pid)

				var totalCount uint64 = 0
				for _, coreCount := range sampleCount {
					totalCount += coreCount
				}

				totalCount *= profiler.SamplePeriod
				myString := fmt.Sprintf("PID : %d USERNAME : %s , number of %s: %d\n", pid, userName, profiler.FileName, totalCount)
				outFile.WriteString(myString)

				err := hook.Update(pid, *zeroValues, ebpf.UpdateAny)
				if err != nil {
					log.Printf("Failed to reset key %d: %v", pid, err)
					return err
				}
			}
		}
	}
}

func OpenFile(fileName string) (*os.File, error) {

	path := "logs/" + fileName

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func getUserForPID(pid uint32) string {
	path := fmt.Sprintf("/proc/%d", pid)
	info, err := os.Stat(path)
	if err != nil {
		return "dead_process"
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uidStr := strconv.Itoa(int(stat.Uid))

		if u, err := user.LookupId(uidStr); err != nil {
			return u.Username
		}
		return uidStr
	}
	return "unknown"
}
