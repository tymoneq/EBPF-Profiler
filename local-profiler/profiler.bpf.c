//go:build ignore

#include <linux/bpf.h>
// linux/bpf.h need to be first inport
#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, __u64);

} switch_counts SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(void* ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;

  __u64* count = bpf_map_lookup_elem(&switch_counts, &pid);

  if (count) {
    __sync_fetch_and_add(count, 1);
  } else {
    __u64 initial = 1;
    bpf_map_update_elem(&switch_counts, &pid, &initial, BPF_ANY);
  }

  return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";