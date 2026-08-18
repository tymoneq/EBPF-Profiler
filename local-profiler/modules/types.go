package modules

import (
	"context"
	"fmt"
	"log"
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
	Wg  sync.WaitGroup
}

func LoadBPFObjects(o *bpfObjects) error {
	return loadBpfObjects(o, nil)
}

func (o *BPFObject) LoadAllTracepoints() ([]link.Link, error) {

	arr := make([]link.Link, 0, 10)

	tp, err := link.AttachTracing(link.TracingOptions{Program: o.Objs.HandleSchedSwitch})
	if err != nil {
		fmt.Printf("Couldn't pin tracepoint: %v \n", err)
		return nil, err
	}
	arr = append(arr, tp)

	tpIssue, err := link.Kretprobe("vfs_read", o.Objs.VfsReadRet, nil)

	if err != nil {
		log.Fatalf("Error hooking vfs read %v\n", err)
		return nil, err
	}
	arr = append(arr, tpIssue)

	tpComplete, err := link.Kretprobe("vfs_write", o.Objs.VfsWriteRet, nil)

	if err != nil {
		log.Fatalf("Error hooking vfs write: %v\n", err)
		return nil, err
	}
	arr = append(arr, tpComplete)

	return arr, nil
}
