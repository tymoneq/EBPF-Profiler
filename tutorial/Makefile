TARGET := hello
TARGET_EBPF := $(TARGET).bpf.o

GO_SRC := *.go
BPF_SCR := *.bpf.c

.PHONY: all clean

all: $(TARGET_EBPF) $(TARGET)

# Używamy -lbpf aby dynamicznie zlinkować bibliotekę z systemem
go_env := CC=clang CGO_CFLAGS="-I/usr/include/bpf" CGO_LDFLAGS="-lbpf"

# Wymuś najpierw kompilację kodu BPF zanim skompilujesz Go
$(TARGET): $(GO_SRC) $(TARGET_EBPF)
	$(go_env) go build -o $(TARGET)

$(TARGET_EBPF): $(BPF_SCR)
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c -o $@ $<

clean:
	go clean
	rm -f $(TARGET_EBPF)