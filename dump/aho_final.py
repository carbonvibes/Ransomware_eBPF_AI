from bcc import BPF
from collections import defaultdict
from time import sleep
import argparse
import subprocess

# Aho-Corasick algorithm (unchanged)
class AhoCorasick:
    def __init__(self, words):
        self.max_states = sum(len(w) for w in words)
        self.max_characters = 26
        self.out = [0] * (self.max_states + 1)
        self.fail = [-1] * (self.max_states + 1)
        self.goto = [[-1] * self.max_characters for _ in range(self.max_states + 1)]
        for i in range(len(words)):
            words[i] = words[i].lower()
        self.words = words
        self.states_count = self.__build_matching_machine()

    def __build_matching_machine(self):
        k = len(self.words)
        states = 1
        for i in range(k):
            w = self.words[i]
            s = 0
            for ch in w:
                idx = ord(ch) - 97
                if self.goto[s][idx] == -1:
                    self.goto[s][idx] = states
                    states += 1
                s = self.goto[s][idx]
            self.out[s] |= (1 << i)

        for c in range(self.max_characters):
            if self.goto[0][c] == -1:
                self.goto[0][c] = 0

        queue = []
        for c in range(self.max_characters):
            if self.goto[0][c] != 0:
                self.fail[self.goto[0][c]] = 0
                queue.append(self.goto[0][c])

        while queue:
            state = queue.pop(0)
            for c in range(self.max_characters):
                if self.goto[state][c] != -1:
                    f = self.fail[state]
                    while self.goto[f][c] == -1:
                        f = self.fail[f]
                    f = self.goto[f][c]
                    self.fail[self.goto[state][c]] = f
                    self.out[self.goto[state][c]] |= self.out[f]
                    queue.append(self.goto[state][c])
        return states

    def __find_next_state(self, s, ch):
        idx = ord(ch) - 97
        while self.goto[s][idx] == -1:
            s = self.fail[s]
        return self.goto[s][idx]

    def search_words(self, text):
        text = text.lower()
        s = 0
        res = defaultdict(list)
        for i, ch in enumerate(text):
            s = self.__find_next_state(s, ch)
            if self.out[s] == 0:
                continue
            for j in range(len(self.words)):
                if (self.out[s] & (1 << j)) > 0:
                    w = self.words[j]
                    res[w].append(i - len(w) + 1)
        return res

# --- BPF program, keyed by ⟨TGID, filename⟩ ---
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>

// Key: TGID + filename (basename)
struct file_id_t {
    u64 tgid;
    char filename[256];
};

struct pattern_t {
    char comm[TASK_COMM_LEN];
    char pattern[36];
    u32 pid;
};

BPF_HASH(patterns, struct file_id_t, struct pattern_t);

// Helper for file-based events (read/write/close/unlink/rename)
static int trace_event_file(struct pt_regs *ctx, struct file *file, char op) {
    struct file_id_t key = {};
    struct pattern_t zero = {};

    u64 id_full = bpf_get_current_pid_tgid();
    u32 tgid = id_full >> 32;
    key.tgid = tgid;

    // copy basename from file->f_path.dentry->d_name.name
    bpf_probe_read_str(key.filename, sizeof(key.filename),
                       file->f_path.dentry->d_name.name);

    struct pattern_t *patt = patterns.lookup_or_init(&key, &zero);
    patt->pid = tgid;
    bpf_get_current_comm(&patt->comm, sizeof(patt->comm));

    int i = 0;
    #pragma unroll
    for (i = 0; i < 35; i++) {
        if (patt->pattern[i] == '\\0') {
            if (i > 0 && patt->pattern[i - 1] == op) {
                break;
            }
            patt->pattern[i] = op;
            patt->pattern[i + 1] = '\\0';
            break;
        }
    }
    return 0;
}

// kfunc probe for vfs_open: append 'O' using path->dentry->d_name.name
KFUNC_PROBE(vfs_open, const struct path *path, struct file *file) {
    struct file_id_t key = {};
    struct pattern_t zero = {};

    u64 id_full = bpf_get_current_pid_tgid();
    u32 tgid = id_full >> 32;
    key.tgid = tgid;

    // copy basename from path->dentry->d_name.name
    bpf_probe_read_str(key.filename, sizeof(key.filename),
                       path->dentry->d_name.name);

    struct pattern_t *patt = patterns.lookup_or_init(&key, &zero);
    patt->pid = tgid;
    bpf_get_current_comm(&patt->comm, sizeof(patt->comm));

    // append 'O'
    int i = 0;
    #pragma unroll
    for (i = 0; i < 35; i++) {
        if (patt->pattern[i] == '\\0') {
            patt->pattern[i] = 'O';
            patt->pattern[i + 1] = '\\0';
            break;
        }
    }
    return 0;
}

// trace read: 'R'
int trace_vfs_read(struct pt_regs *ctx, struct file *file) {
    return trace_event_file(ctx, file, 'R');
}

// trace write: 'W'
int trace_vfs_write(struct pt_regs *ctx, struct file *file) {
    return trace_event_file(ctx, file, 'W');
}

// trace rename: 'P'
int trace_vfs_rename(struct pt_regs *ctx, struct inode *old_dir,
                     struct dentry *old_dentry, struct inode *new_dir,
                     struct dentry *new_dentry) {
    struct file_id_t key = {};
    struct pattern_t zero = {};

    u64 id_full = bpf_get_current_pid_tgid();
    u32 tgid = id_full >> 32;
    key.tgid = tgid;

    // copy basename from old_dentry->d_name.name
    bpf_probe_read_str(key.filename, sizeof(key.filename),
                       old_dentry->d_name.name);

    struct pattern_t *patt = patterns.lookup_or_init(&key, &zero);
    patt->pid = tgid;
    bpf_get_current_comm(&patt->comm, sizeof(patt->comm));

    int i = 0;
    #pragma unroll
    for (i = 0; i < 35; i++) {
        if (patt->pattern[i] == '\\0') {
            if (i > 0 && patt->pattern[i - 1] == 'P') {
                break;
            }
            patt->pattern[i] = 'P';
            patt->pattern[i + 1] = '\\0';
            break;
        }
    }
    return 0;
}

// trace filp_close: 'L'
int trace_filp_close(struct pt_regs *ctx, struct file *filp,
                     unsigned long id, int retval) {
    return trace_event_file(ctx, filp, 'L');
}

// trace unlink: 'U'
int trace_vfs_unlink(struct pt_regs *ctx, struct inode *dir,
                     struct dentry *dentry) {
    struct file_id_t key = {};
    struct pattern_t zero = {};

    u64 id_full = bpf_get_current_pid_tgid();
    u32 tgid = id_full >> 32;
    key.tgid = tgid;

    // copy basename from dentry->d_name.name
    bpf_probe_read_str(key.filename, sizeof(key.filename),
                       dentry->d_name.name);

    struct pattern_t *patt = patterns.lookup_or_init(&key, &zero);
    patt->pid = tgid;
    bpf_get_current_comm(&patt->comm, sizeof(patt->comm));

    int i = 0;
    #pragma unroll
    for (i = 0; i < 35; i++) {
        if (patt->pattern[i] == '\\0') {
            if (i > 0 && patt->pattern[i - 1] == 'U') {
                break;
            }
            patt->pattern[i] = 'U';
            patt->pattern[i + 1] = '\\0';
            break;
        }
    }
    return 0;
}
"""

# CLI args
parser = argparse.ArgumentParser(
    description="Trace VFS calls and accumulate patterns per ⟨TGID, filename⟩ using kfunc:vmlinux:vfs_open.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="example: sudo python3 aho.py 2 --threshold 10"
)
parser.add_argument("interval", nargs="?", default=1,
                    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
                    help="number of outputs")
parser.add_argument("--threshold", type=int, default=10,
                    help="threshold for killing processes")

args = parser.parse_args()
countdown = int(args.count)

# Load & attach BPF
b = BPF(text=bpf_text)
# Attach kfunc probe for vfs_open (path-based) using BCC’s attach_kfunc
#b.attach_kfunc("vfs_open") this is incorrect format
# Other events via kprobe
b.attach_kprobe(event="vfs_read", fn_name="trace_vfs_read")
b.attach_kprobe(event="vfs_write", fn_name="trace_vfs_write")
b.attach_kprobe(event="vfs_rename", fn_name="trace_vfs_rename")
b.attach_kprobe(event="filp_close", fn_name="trace_filp_close")
b.attach_kprobe(event="vfs_unlink", fn_name="trace_vfs_unlink")

# Aho-Corasick patterns
patterns = ["ORWOWP", "ORWRWP", "ORWP", "OWRWRWRWP", "OWRWP", "ORWRWOWP"]
aho_cor = AhoCorasick(patterns)

# Main loop
while True:
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        break

    print("%-8s  %-16s  %-32s  %-16s" % ("TGID", "COMM", "FILENAME", "PATTERN"))
    patterns_table = b.get_table("patterns")

    for key, val in patterns_table.items():
        tgid = val.pid
        comm = val.comm.decode('utf-8', 'replace')
        fname = key.filename.decode('utf-8', 'replace')
        pat = val.pattern.decode('utf-8', 'replace')

        detected = aho_cor.search_words(pat)
        count_matches = sum(len(lst) for lst in detected.values())
        if count_matches > args.threshold:
            print(f"Pattern '{list(detected.keys())}' exceeded {args.threshold}.")
            try:
                subprocess.run(["sudo", "killall", "-9", comm])
                print(f"Killed {tgid} ({comm}).")
            except Exception as e:
                print(f"Failed to kill {tgid}: {e}")

        print("%-8d  %-16s  %-32s  %-16s" % (tgid, comm, fname, pat))
    patterns_table.clear()
