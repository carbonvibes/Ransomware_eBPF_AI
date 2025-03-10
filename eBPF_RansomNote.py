from bcc import BPF
import ctypes
import os
import subprocess
import time
import pickle
import nltk
import string
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
import sys

location='/home/parallels/Ransomware_eBPF_AI/model.pkl' #replace this with actual loaction

with open(location, 'rb') as f:
    vectorizer_tfidf, selector, rf_model = pickle.load(f)

nltk.data.path.append("/root/nltk_data")
nltk.download('punkt', quiet=True)
nltk.download('stopwords', quiet=True)
nltk.download('wordnet', quiet=True)

def preprocess_text(text):
    if isinstance(text, str):
        tokens = nltk.word_tokenize(text.lower())
        translator = str.maketrans('', '', string.punctuation)
        tokens = [token.translate(translator) for token in tokens]
        stop_words = set(stopwords.words('english'))
        tokens = [token for token in tokens if token not in stop_words]
        lemmatizer = WordNetLemmatizer()
        tokens = [lemmatizer.lemmatize(token) for token in tokens]
        return tokens
    return []

def predict_from_text(custom_text, pid, comm):
    processed_text = preprocess_text(custom_text)
    joined_text = ' '.join(processed_text)
    tfidf_features = vectorizer_tfidf.transform([joined_text])
    if selector is not None:
        tfidf_features = selector.transform(tfidf_features)
    prediction = rf_model.predict(tfidf_features)[0]
    if prediction == 1:
        print(f"Ransomware process {pid} {comm} detected")
        try:
            print(f"Attempting to kill process {pid} ({comm})...")
            subprocess.run(["sudo", "kill", "-9", str(pid)], check=True)
            print(f"Process {pid} {comm} has been killed.")
        except subprocess.CalledProcessError as e:
            print(f"Error killing process {pid} {comm}: {e}")
    else:
        print(f"Process {pid} {comm} is benign.")

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/fcntl.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (uid != 1000)
        return 0;

    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Exclude specific commands
    const char *comm = data.comm;
    if (comm == NULL)
        return 0;


    // Check if O_CREAT flag is set
    if ((args->flags & O_CREAT) == 0)
        return 0;

    // Copy filename
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=bpf_text)
TASK_COMM_LEN = 16
NAME_MAX = 255

class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("filename", ctypes.c_char * NAME_MAX)
    ]

print("Tracing... Press Ctrl-C to end.")

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    pid = event.pid
    filename = event.filename.decode('utf-8', 'replace')
    comm = event.comm.decode('utf-8', 'replace')
    
    try:
        if not os.path.isabs(filename):
            proc_cwd = f"/proc/{pid}/cwd"
            cwd = os.readlink(proc_cwd) if os.path.exists(proc_cwd) else '/'
            filename_full = os.path.join(cwd, filename)
        else:
            filename_full = filename
        
        with open(filename_full, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"File {filename_full} not found. Skipping...")
        return
    except PermissionError:
        print(f"Permission denied: {filename_full}. Skipping...")
        return
    except Exception as e:
        print(f"Could not read file {filename}: {e}")
        return
    
    if content:
        predict_from_text(content, pid, comm)

b["events"].open_perf_buffer(print_event, page_cnt=64)
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Detaching...")
    sys.exit(0)
