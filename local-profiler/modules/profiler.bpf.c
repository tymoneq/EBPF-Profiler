//go:build ignore

#include "../include/vmlinux.h"
// linux/bpf.h need to be first inport
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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

// Mapa histogramu (np. 32 przedziały czasowe)
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, struct io_stats);
} process_io_stats SEC(".maps");

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

// context switches
SEC("tracepoint/sched/sched_switch") int handle_sched_switch(void* ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;

  __u64* count = bpf_map_lookup_elem(&switch_counts, &pid);

  if (count != NULL)
    *count += 1;
  else {
    __u64 initial_count = 1;
    bpf_map_update_elem(&switch_counts, &pid, &initial_count, BPF_ANY);
  }
  return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";