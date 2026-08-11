TARGET := hello
TARGET_EBPF := $(TARGET).bpf.o

GO_SRC := *.go
BPF_SCR := *.bpf.c

LIBBPF_HEADERS := /usr/include/bpf
LIBBPF_OBJ := /usr/lib/libbpf.a

.PHONY: all

all: $(TARGET) $(TARGET_EBPF)

go_env := CC=clang CGO_CFLAGS="-I $(LIBBPF_HEADERS)" CGO_LDFLAGS="$(LIBBOF_OBJ)"

$(TARGET): $(GO_SRC)
	$(go_env) go build -o $(TARGET)

$(TARGET_EBPF): $(BPF_SCR)
	clang -O2 -target bpf -D__TARGET_ARCH_x86 -c -o $@ $<

.PHONY: clean
clean:
	go clean
