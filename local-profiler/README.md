# Local eBPF Profiler

This project is a small Linux eBPF profiler written in Go. It loads BPF programs from the C file in `modules/profiler.bpf.c`, attaches them to kernel events, and periodically writes summaries to files in the `logs/` directory.

The profiler tracks:

- Context switches
- Run queue latency
- Disk I/O read/write activity
- Cache misses
- Page faults

It is intended for local Linux performance analysis on a host machine where you have access to the kernel and BPF tooling.

---

## Requirements

Before running this project, make sure your machine meets the following:

- Linux kernel with BPF support enabled
- Root privileges or at least `CAP_BPF` and `CAP_SYS_ADMIN`
- `x86_64` architecture (the generated BPF code is targeted to amd64)
- Go installed
- `clang`, `llvm`, `bpftool`, and Linux kernel headers available
- `task` (optional, but used by the included Taskfile)

You can check whether the necessary tools are installed with:

```bash
uname -m
uname -r
go version
clang --version
bpftool --version
```

If `bpftool` is missing:

```bash
sudo apt update
sudo apt install bpftool clang llvm linux-headers-$(uname -r)
```

On Fedora/RHEL-based systems:

```bash
dnf install bpftool clang llvm kernel-devel
```

---

## What this program does

The main application starts multiple goroutines, each monitoring a different performance signal:

- `ContextSwitches` writes active process context-switch counts
- `RunqLatency` records run-queue latency histogram buckets
- `GetDiskLatency` measures read and write bytes/counts per process
- `CacheMisses` counts hardware cache misses
- `PageFaults` records minor and major page faults

The application listens for `Ctrl+C` (`SIGINT`/`SIGTERM`) and then waits for all goroutines to finish writing their final data before exiting.

---

## Repository layout

```text
.
├── main.go
├── go.mod
├── Taskfile.yml
├── include/
│   └── vmlinux.h
├── logs/
├── modules/
│   ├── profiler.bpf.c
│   ├── bpf_x86_bpfel.go
│   ├── cache_misses.go
│   ├── context_switches.go
│   ├── disk_latency.go
│   ├── page_faults.go
│   ├── runq_latency.go
│   ├── types.go
│   └── utils.go
├── prometheus-server/
│   └── server.go
└── README.md
```

The important file is `modules/profiler.bpf.c`; it includes `include/vmlinux.h` and attaches to:

- `sched_wakeup`
- `sched_switch`
- `vfs_read`
- `vfs_write`
- `handle_mm_fault`

---

## How to get `vmlinux.h`

### Recommended method: use the kernel BTF info

This project expects a generated `vmlinux.h` file that contains kernel type definitions. The usual and cleanest way is to dump the kernel BTF from `/sys/kernel/btf/vmlinux`.

Run:

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
```

This generates the file at:

```text
include/vmlinux.h
```

This is the preferred method because it matches the exact kernel you are running and avoids manual header mismatches.

### If `bpftool` cannot find `/sys/kernel/btf/vmlinux`

This usually means one of the following:

- your kernel does not expose BTF
- you are running inside a container without access to the host kernel
- your distro/kernel is missing the BTF feature

In that case, you need to either:

1. run this on the host machine, not a container, or
2. install a kernel with BTF enabled, or
3. install the matching kernel headers and generate the header from a kernel build tree.

If your distro has BTF support but it is not active yet, check:

```bash
ls -l /sys/kernel/btf/
```

If that directory is missing, the kernel is not exposing BTF information.

### Alternative: use matching kernel headers

If you are building against a specific kernel source tree, you can use the kernel headers as a fallback, but this project is specifically written to include the generated `vmlinux.h` structure used by BPF code generation.

In most cases, the `bpftool` BTF dump method above is the easiest and most reliable solution.

---

## Build the project

The project contains a generated BPF stub and a Go build process. The included `Taskfile.yml` defines the standard build steps.

### Option 1: using Task

```bash
go install github.com/go-task/task/v3/cmd/task@latest
# or: sudo apt install task

task build
```

This runs:

```bash
go generate ./modules
go build -o app
```

### Option 2: build manually

Generate the Go bindings from the C BPF program:

```bash
go generate ./modules
```

Then build the binary:

```bash
go build -o app
```

---

## Run the profiler

Run the binary as root:

```bash
sudo ./app
```

You should see output like:

```text
Enter ctrl-c to stop profiler

CPU Profiler is working, listening for context switches...
I/O profiler started. Collecting data...
...
```

Then press `Ctrl+C` to stop it. The program will wait for goroutines to finish and clean up.

---

## Output files

As the profiler runs, it writes summaries to files in the `logs/` directory. The current project writes files such as:

- `logs/contexStiches.log`
- `logs/IOReadWrite.log`
- `logs/runqLatency.log`
- `logs/cacheMisses.log`
- `logs/pageFaults.log`

The output is updated periodically using ticker intervals defined in each module:

- context switches: every 1 second
- cache misses: every 5 seconds
- disk I/O: every 5 seconds
- run queue latency: every 5 seconds
- page faults: every 5 seconds

---

## Example workflow

```bash
cd /path/to/local-profiler

# ensure vmlinux.h exists
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h

# build
go generate ./modules
go build -o app

# run
sudo ./app
```

After a few seconds, inspect the files:

```bash
ls -l logs/
cat logs/runqLatency.log
cat logs/pageFaults.log
```

---

## Troubleshooting

### `Couldn't load eBPF objects`

This usually means one of the following:

- missing `vmlinux.h`
- unsupported kernel features
- insufficient privileges
- wrong architecture target

Check whether you are running as root and whether the kernel exposes BTF.

### `operation not permitted`

Run the program with sudo, or ensure the user has the required Linux capabilities. This project attaches kernel probes and perf events, which requires elevated privileges.

### `no such file or directory: include/vmlinux.h`

Generate it with:

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
```

### `failed to load BPF program`

Common causes:

- mismatched kernel and generated header definitions
- missing `clang`/`llvm` or kernel headers
- running inside a constrained container environment

---

## Notes

- This is a local profiler focused on host Linux performance monitoring.
- It is not a general-purpose distributed tracing system.
- The generated BPF code is architecture-specific and is explicitly set for `amd64` in the Go generator comment.
- If you migrate to a different kernel version, regenerate `vmlinux.h` to ensure the BPF definitions match the running kernel.

---

## Quick start summary

```bash
sudo apt install bpftool clang llvm linux-headers-$(uname -r)
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
go generate ./modules
go build -o app
sudo ./app
```

If you want to keep everything in one command set:

```bash
task build && sudo ./app
```
