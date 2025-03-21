#!/usr/bin/python3
from bcc import BPF
import pandas as pd
import ctypes
import hashlib
import os
import subprocess

# File path of the CSV
csv_file = "/home/parallels/Downloads/static.csv"  

# Load the CSV file into a pandas DataFrame
try:
    df = pd.read_csv(csv_file, header=None, dtype=str)  # Assuming no header, single-column file
    print(f"Loaded {len(df)} SHA256 hashes from '{csv_file}'.")
except FileNotFoundError:
    print(f"Error: File '{csv_file}' not found.")
    df = pd.DataFrame()  
  
# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>  // For O_CREAT flag

struct val_t {
    char filename[256];
    int flags;
};
BPF_HASH(opens, u32, struct val_t);
BPF_HASH(fds, u64, struct val_t);
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    int flags = args->flags;
    // Check if O_CREAT flag is set
    if (!(flags & O_CREAT))
        return 0;

    struct val_t val = {};
    bpf_probe_read_user_str(&val.filename, sizeof(val.filename), args->filename);
    val.flags = flags;
    opens.update(&pid, &val);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct val_t *valp = opens.lookup(&pid);
    if (valp == 0)
        return 0;

    int fd = args->ret;
    if (fd < 0)
    {
        opens.delete(&pid);
        return 0;
    }

    u64 pid_fd = ((u64)pid << 32) | fd;
    fds.update(&pid_fd, valp);

    opens.delete(&pid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_close)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int fd = args->fd;

    u64 pid_fd = ((u64)pid << 32) | fd;
    struct val_t *valp = fds.lookup(&pid_fd);
    if (valp == 0)
        return 0;

    struct data_t {
        u32 pid;
        char comm[TASK_COMM_LEN];
        char filename[256];
    } data = {};

    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.filename, valp->filename, sizeof(data.filename));

    events.perf_submit(args, &data, sizeof(data));

    fds.delete(&pid_fd);
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_text)
TASK_COMM_LEN = 16 
class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("filename", ctypes.c_char * 256)
    ]

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    filename = event.filename.decode('utf-8', 'replace')
    print(f"New File Created by {event.comm.decode('utf-8')} (PID: {event.pid}): {filename}")

    filepath = filename
    if not os.path.isabs(filepath):
        # If the path is not absolute, try to resolve it (best effort)
        filepath = os.path.join("/proc", str(event.pid), "cwd", filename)
        filepath = os.path.realpath(filepath)

    try:
        with open(filepath, 'rb') as f:
            file_content = f.read()
            sha256_hash = hashlib.sha256(file_content).hexdigest()
            print(f"SHA256 Hash: {sha256_hash}")

            # Check if the hash exists in the preloaded CSV DataFrame
            if sha256_hash in df[0].values:  # Assuming the hash column is the first one
                print(f"The SHA256 hash {sha256_hash} is present in the CSV file.\n")
                os.remove(str(filepath))
                print(f"Malicious file: {filepath} removed from the disk")
            else:
                print(f"The SHA256 hash {sha256_hash} is NOT present in the CSV file.\n")

    except Exception as e:
        print(f"Could not read file {filepath}: {e}\n")

b["events"].open_perf_buffer(print_event)

print("Monitoring new file creations... Press Ctrl+C to exit.")
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Exiting...")
