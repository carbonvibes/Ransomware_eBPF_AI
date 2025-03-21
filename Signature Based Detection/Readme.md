## Static Analysis

eBPF tracepoints are used to monitor file creation operations to detect and prevent malicious files from persisting on the system. 

### Monitoring File Creation  
First, the `openat` system call is intercepted when it includes the `O_CREAT` flag, indicating an attempt to create a new file. At this stage, the filename and flags are captured and stored in a temporary hash map indexed by the process ID. Upon exit of the `openat` system call, this information is correlated with the system call’s return value to obtain the file descriptor. 

This correlation is crucial because it allows tracking of only successfully created files and associates each file descriptor with its corresponding process ID. This mapping is stored in another hash map keyed by a combination of process ID and file descriptor. 

### Deferred Analysis on File Close  
The analysis is deferred until the file closing operation before performing any operations. The associated filename and process information are retrieved when a process invokes the `close` system call on a tracked file descriptor. This wait time ensures that all write operations to the file have been completed, making the file content stable and suitable for a hash to be computed. 

### Hash-Based Malware Detection  
Once the file is closed, its SHA-256 hash is calculated by reading the file content from the disk. This hash is then compared against a preloaded database consisting of SHA-256 hashes of about 862,406 malware samples obtained from [MalwareBazaar](https://bazaar.abuse.ch/). If a match is found, indicating the presence of a known malicious file, the system immediately removes the file from the disk, preventing potential execution or further system compromise. 

### Performance and Security  
This static analysis layer serves as an initial defense mechanism, offering real-time detection capabilities while maintaining system performance. The approach operates at the kernel level, providing comprehensive monitoring of file creation activities across the system without requiring signature scanning of every file operation, which would introduce significant overhead when implemented in user space.
