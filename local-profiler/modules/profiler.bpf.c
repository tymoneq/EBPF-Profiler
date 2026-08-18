//go:build ignore

#include "../include/vmlinux.h"
// linux/bpf.h need to be first inport
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, __u64);

} sched_times SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 32);
  __type(key, u32);
  __type(value, u64);
} runq_histogram SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, __u64);

} switch_counts SEC(".maps");

struct io_stats {
  __u64 read_bytes;
  __u64 write_bytes;
  __u64 read_count;
  __u64 write_count;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, struct io_stats);
} process_io_stats SEC(".maps");

// runq latency
SEC("tp_btf/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct* p) {
  u32 pid = p->pid;
  u64 ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&sched_times, &pid, &ts, BPF_ANY);
  return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(handle_sched_switch,
             bool preempt,
             struct task_struct* prev,
             struct task_struct* next) {
  // context switches
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;

  __u64* count = bpf_map_lookup_elem(&switch_counts, &pid);

  if (count != NULL)
    *count += 1;
  else {
    __u64 initial_count = 1;
    bpf_map_update_elem(&switch_counts, &pid, &initial_count, BPF_ANY);
  }

  //  calculating runqueue latency

  u32 next_tid = next->pid;
  u64 *start_ts, delta_us;
  u32 slot;

  start_ts = bpf_map_lookup_elem(&sched_times, &next_tid);
  if (start_ts != NULL) {
    delta_us = (bpf_ktime_get_ns() - *start_ts) / 1000;
    slot = 64 - __builtin_clzll(delta_us);
    if (slot >= 32)
      slot = 31;

    u64* hist_count = bpf_map_lookup_elem(&runq_histogram, &slot);
    if (hist_count != NULL) {
      *hist_count += 1;
    } else {
     __u64 initial_count = 1;
      bpf_map_update_elem(&runq_histogram, &slot, &initial_count, BPF_ANY);
    }
    bpf_map_delete_elem(&sched_times, &next_tid);
  }
  return 0;
}

// disk latency
SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(vfs_read_ret, long ret) {
  if (ret <= 0)
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;

  struct io_stats* stats = bpf_map_lookup_elem(&process_io_stats, &pid);
  if (stats != NULL) {
    stats->read_bytes += ret;
    stats->read_count += 1;
  } else {
    struct io_stats new_stats = {
        .read_bytes = ret, .read_count = 1, .write_bytes = 0, .write_count = 0};
    bpf_map_update_elem(&process_io_stats, &pid, &new_stats, BPF_ANY);
  }
  return 0;
}

SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(vfs_write_ret, long ret) {
  if (ret <= 0)
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;

  struct io_stats* stats = bpf_map_lookup_elem(&process_io_stats, &pid);
  if (stats != NULL) {
    stats->write_bytes += ret;
    stats->write_count += 1;
  } else {
    struct io_stats new_stats = {
        .read_bytes = 0, .read_count = 0, .write_bytes = ret, .write_count = 1};
    bpf_map_update_elem(&process_io_stats, &pid, &new_stats, BPF_ANY);
  }
  return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";