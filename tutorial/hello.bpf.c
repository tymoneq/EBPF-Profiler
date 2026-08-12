#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

// Nowoczesna deklaracja mapy typu Perf Event Array (zamiast BPF_PERF_OUTPUT)
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} gotopia SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int hello(void* ctx) {
  char data[30];
  bpf_get_current_comm(&data, sizeof(data));
  bpf_perf_event_output(ctx, &gotopia, BPF_F_CURRENT_CPU, &data, sizeof(data));

  return 0;
}

char _license[] SEC("license") = "GPL";