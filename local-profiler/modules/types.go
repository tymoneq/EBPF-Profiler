package modules

import (
	"context"
	"fmt"
	"sync"

	"github.com/cilium/ebpf/link"
)

// Magiczna komenda, która łączy C z Go. Kompiluje kod pod architekturę x86_64.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf profiler.bpf.c

type BPFObject struct {
	Objs    bpfObjects
	NumCPUs int
}

type SyncStruct struct {
	Ctx context.Context
	Wg  *sync.WaitGroup
}

func LoadBPFObjects(o *bpfObjects) error {
	return loadBpfObjects(o, nil)
}

func appendTracepoint(err error, tp *link.Link, arr *[]link.Link) error {
	if err != nil {
		fmt.Printf("Couldn't pin tracepoint: %v \n", err)
		return err
	}
	*arr = append(*arr, *tp)
	return nil
}

func (o *BPFObject) LoadAllTracepoints() ([]link.Link, error) {

	arr := make([]link.Link, 0, 10)

	tp, err := link.AttachTracing(link.TracingOptions{Program: o.Objs.HandleSchedSwitch})
	if err := appendTracepoint(err, &tp, &arr); err != nil {
		return nil, err
	}

	sched_wakeup, err := link.AttachTracing(link.TracingOptions{Program: o.Objs.HandleSchedWakeup})
	if err := appendTracepoint(err, &sched_wakeup, &arr); err != nil {
		return nil, err
	}

	tpIssue, err := link.Kretprobe("vfs_read", o.Objs.VfsReadRet, nil)
	if err := appendTracepoint(err, &tpIssue, &arr); err != nil {
		return nil, err
	}

	tpComplete, err := link.Kretprobe("vfs_write", o.Objs.VfsWriteRet, nil)
	if err := appendTracepoint(err, &tpComplete, &arr); err != nil {
		return nil, err
	}

	return arr, nil
}
