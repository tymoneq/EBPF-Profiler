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

type Combinable[T any] interface {
	Add(other T) T
	Mul(scalar uint64) T
}

type ProfilerUint uint64

func (u ProfilerUint) Add(other ProfilerUint) ProfilerUint {
	return u + other
}

func (u ProfilerUint) Mul(scalar uint64) ProfilerUint {
	return u * ProfilerUint(scalar)
}

type ProfilerData[T Combinable[T]] struct {
	zeroValues *[]T
	totalCount *T
}

type ProfilerStruct struct {
	SamplePeriod    uint64
	TimeInterval    int
	FileName        string
	ProfilerMessage string
	sync            *synchronization.SyncStruct
}

func (p *ProfilerData[T]) AddToTotal(val T) {
	if p.totalCount == nil {
		p.totalCount = new(T)
	}
	*p.totalCount = (*p.totalCount).Add(val)
}

func (p *ProfilerData[T]) MulToTotal(scalar uint64) {
	if p.totalCount == nil {
		p.totalCount = new(T)
	}
	*p.totalCount = (*p.totalCount).Mul(scalar)
}

func (p *ProfilerData[T]) ResetTotalCount() {
	if p.totalCount == nil {
		p.totalCount = new(T)
	} else {
		*p.totalCount = *new(T)
	}

}

func writeDataHeader(t time.Time, FileName *string, outFile *os.File) {

	t = time.Now()
	t.Format("2006-01-02 15:04:05")

	outString := fmt.Sprintf("---%s---\n", *FileName)
	outFile.WriteString(outString)
	outFile.WriteString(t.Format("2006-01-02 15:04:05") + "\n")

}

func RunGoRoutine[T Combinable[T]](profiler *ProfilerStruct, hook *ebpf.Map, profData ProfilerData[T]) error {

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

			writeDataHeader(t, &profiler.FileName, outFile)

			var pid uint32
			var data []T
			var iter = hook.Iterate()

			for iter.Next(&pid, &data) {
				userName := getUserForPID(pid)

				profData.ResetTotalCount()
				for _, coreCount := range data {
					profData.AddToTotal(coreCount)
				}

				profData.MulToTotal(profiler.SamplePeriod)

				myString := fmt.Sprintf("PID : %d USERNAME : %s , number of %s: %+v\n", pid, userName, profiler.FileName, *profData.totalCount)
				outFile.WriteString(myString)

				err := hook.Update(pid, (*profData.zeroValues), ebpf.UpdateAny)
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
