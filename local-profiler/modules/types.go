package modules

// Magiczna komenda, która łączy C z Go. Kompiluje kod pod architekturę x86_64.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf profiler.bpf.c

type BPFObject struct {
	Objs bpfObjects
}

func LoadBPFObjects(o *bpfObjects) error {
	return loadBpfObjects(o, nil)
}
