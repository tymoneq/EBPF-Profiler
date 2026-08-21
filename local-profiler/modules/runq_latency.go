package modules

import (
	"fmt"
	"log"
	"math"
	"sort"
	"time"

	synchronization "local-profiler/synchronization"

	"github.com/cilium/ebpf"
)

type HistogramBucket struct {
	Slot       uint32
	LowerBound uint64
	UpperBound uint64
	Count      uint64
}

func (o BPFObject) RunqLatency(sync *synchronization.SyncStruct) error {
	defer sync.Wg.Done()

	outFile, err := OpenFile("runqLatency.log")
	if err != nil {
		log.Printf("Error opening a file : %v\n", err)
		return err
	}
	defer outFile.Close()

	zeroValues := make([]uint64, o.NumCPUs)

	fmt.Println("CPU Profiler is working, listening for runq latency...")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sync.Ctx.Done():
			fmt.Println("closing runq latency")
			return nil

		case t := <-ticker.C:
			t = time.Now()
			t.Format("2006-01-02 15:04:05")

			outFile.WriteString("---Histogram of Runq Latency---")
			outFile.Write([]byte(t.String()))
			outFile.WriteString("\n")

			var slot uint32
			var perCPUValues []uint64

			var buckets []HistogramBucket

			iter := o.Objs.RunqHistogram.Iterate()
			for iter.Next(&slot, &perCPUValues) {

				var totalCount uint64 = 0
				for _, coreCount := range perCPUValues {
					totalCount += coreCount
				}
				if totalCount > 0 {
					lowerBound := uint64(0)
					if slot > 0 {
						lowerBound = uint64(math.Pow(2, float64(slot-1)))
					}
					upperBound := uint64(math.Pow(2, float64(slot)))

					buckets = append(buckets, HistogramBucket{
						Slot:       slot,
						LowerBound: lowerBound,
						UpperBound: upperBound,
						Count:      totalCount,
					})
				}

				err := o.Objs.RunqHistogram.Update(slot, zeroValues, ebpf.UpdateAny)
				if err != nil {
					log.Printf("Failed to reset key %d: %v", slot, err)
					return err
				}
			}
			sort.Slice(buckets, func(i, j int) bool {
				return buckets[i].Slot < buckets[j].Slot
			})
			for _, b := range buckets {
				outString := fmt.Sprintf("[%6d us - %6d us] : %d runq latency\n", b.LowerBound, b.UpperBound, b.Count)
				outFile.WriteString(outString)
			}
		}

	}
}
