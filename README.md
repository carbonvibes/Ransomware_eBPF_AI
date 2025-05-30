# Ransomware Detection using eBPF and Machine Learning
<div align='justify'>
  
This project leverages **eBPF (Extended Berkeley Packet Filter)** to monitor file operations and a **machine learning model** to detect ransomware behavior in real-time. When ransomware activity is detected, the process is automatically terminated.

## Abstract
<div align='justify'>
  
In this work, we propose a two-phased approach to detect and deter ransomware in real-time. We leverage the capabilities of eBPF (Extended Berkeley Packet Filter) and artificial intelligence (AI) to develop proactive and reactive methods. In the first phase, we utilize signature-based detection, where we employ custom eBPF programs to trace the execution of new processes and perform hash-based analysis against a known ransomware dataset. In the second, we employ a behavior-based technique that focuses on monitoring the process activities using a custom eBPF program and the creation of ransom notes — a prominent indicator of ransomware activity through the use of Natural Language Processing (NLP). By leveraging eBPF’s low-level tracing capabilities and integrating NLP-based machine learning algorithms, our solution achieves an impressive **99.79% accuracy** in identifying ransomware incidents within a few seconds on the onset of zero-day attacks.


This work is part of **LeARN: Leveraging eBPF and AI for Ransomware Nose Out** and is published in **COMSNETS'25 CSP proceedings**. You can take a look at the attached research paper for more details.

## Installation
To run this project, ensure you have the required dependencies installed.

### Step 1: Install Kernel Headers
Kernel headers are required for eBPF programs to function correctly.

```bash
sudo apt-get update
sudo apt-get install -y linux-headers-$(uname -r)
```

### Step 2: Install BPF Tools
Install `bcc`, `bpfcc-tools`, and related dependencies.

```bash
sudo apt-get install -y bpfcc-tools libbpfcc libbpfcc-dev python3-bpfcc
```

### Step 3: Install bpftrace
Install `bpftrace` to facilitate eBPF debugging and tracing.

```bash
sudo apt-get install -y bpftrace
```

### Step 4: Set Up a Python Virtual Environment
It is recommended that a virtual environment for Python dependencies be created while using system-installed eBPF tools.

```bash
python3 -m venv bcc_env --system-site-packages
source bcc_env/bin/activate
```


### Step 5: Install Python Dependencies
Ensure you have Python 3 and pip installed. Then, install the necessary Python libraries inside the virtual environment.

```bash
pip install numpy scikit-learn nltk pandas
```

### Step 6: Download NLTK Resources
First run the below bash command before downloading the ntlk resources, to ensure that nltk resources are downloaded in the virtual environment.

```bash
sudo $(which python)
```

```python
import nltk

nltk.download('punkt_tab')
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('wordnet')
```

### Step 7: Place the ML Model in the Correct Location
Ensure that the pre-trained `model.pkl` file is downloaded and change the `location` variable accordingly.

## Running the Program
To start monitoring for ransomware activity, run:

```bash
source bcc_env/bin/activate
sudo $(which python) eBPF_RansomNote.py
```

### Expected Output
- If ransomware activity is detected, the process is killed.
- If the process is benign, it is allowed to continue execution.

## How It Works
1. The **eBPF program** attaches to the `sys_enter_openat` tracepoint and captures file creations.
2. The filename and process ID (PID) are extracted.
3. If the file can be read, its content is preprocessed using NLP.
4. The **TF-IDF vectorizer** and **Random Forest model** predict whether the process is ransomware.
5. If classified as ransomware, the process is terminated.
