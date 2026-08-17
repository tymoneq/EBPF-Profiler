//go:build ignore

#include <linux/bpf.h>
// linux/bpf.h need to be first inport
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, __u64);

} switch_counts SEC(".maps");

// Mapa przechowująca czasy rozpoczęcia operacji I/O
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, struct request*);
  __type(value, __u64);
} start_times SEC(".maps");

// Mapa histogramu (np. 32 przedziały czasowe)
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 32);
  __type(key, __u32);
  __type(value, __u64);
} io_histogram SEC(".maps");

// disk send request
SEC("tp_btf/block_rq_issue")
int BPF_PROG(handle_block_rq_issue, struct request* rq) {
  __u64 ts = bpf_ktime_get_ns();

  bpf_map_update_elem(&start_times, &rq, &ts, BPF_ANY);
  return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(handle_block_rq_complete,
             struct request* rq,
             int error,
             unsigned int nr_bytes) {
  __u64 *start_ts, delta_us;
  __u32 slot;

  start_ts = bpf_map_lookup_elem(&start_times, &rq);
  if (start_ts == NULL)
    return 0;

  delta_us = (bpf_ktime_get_ns() - *start_ts) / 1000;

  slot = 64 - __builtin_clzll(delta_us);
  if (slot >= 32)
    slot = 31;

  __u64* count = bpf_map_lookup_elem(&io_histogram, &slot);
  if (count != NULL)
    *count += 1;
  return 0;
}

// context switches
SEC("tracepoint/sched/sched_switch") int handle_sched_switch(void* ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;

  __u64* count = bpf_map_lookup_elem(&switch_counts, &pid);

  if (count != NULL)
    *count += 1;

  return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";