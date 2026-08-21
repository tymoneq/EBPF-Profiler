package modules

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Magiczna komenda, która łączy C z Go. Kompiluje kod pod architekturę x86_64.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf profiler.bpf.c
type HookType int32

const (
	AttachTracing = iota
	Kretprobe
)

type BPFObject struct {
	Objs    bpfObjects
	NumCPUs int
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

func linkTracepoint(arr *[]link.Link, HandleSchedSwitch *ebpf.Program, hookType HookType, kprogeName string) error {

	if hookType == AttachTracing {
		tp, err := link.AttachTracing(link.TracingOptions{Program: HandleSchedSwitch})
		if err := appendTracepoint(err, &tp, arr); err != nil {
			return err
		}
	} else if hookType == Kretprobe {
		tp, err := link.Kretprobe(kprogeName, HandleSchedSwitch, nil)
		if err := appendTracepoint(err, &tp, arr); err != nil {
			return err
		}
	}

	return nil
}

func (o *BPFObject) LoadAllTracepoints() ([]link.Link, error) {
	const NUMBER_OF_TRACE_POINTS = 10
	arr := make([]link.Link, 0, NUMBER_OF_TRACE_POINTS)

	if err := linkTracepoint(&arr, o.Objs.HandleSchedSwitch, AttachTracing, ""); err != nil {
		return nil, err
	}

	if err := linkTracepoint(&arr, o.Objs.HandleSchedWakeup, AttachTracing, ""); err != nil {
		return nil, err
	}

	if err := linkTracepoint(&arr, o.Objs.VfsReadRet, Kretprobe, "vfs_read"); err != nil {
		return nil, err
	}

	if err := linkTracepoint(&arr, o.Objs.VfsWriteRet, Kretprobe, "vfs_write"); err != nil {
		return nil, err
	}

	if err := linkTracepoint(&arr, o.Objs.HandleMmFaultRet, Kretprobe, "handle_mm_fault"); err != nil {
		return nil, err
	}

	return arr, nil
}
