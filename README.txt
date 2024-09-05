#Rust Malware Scanner, MEWTWO


Malware Scanner in Memory-Safe Rust for Buffer Overflow (NOP Sled) and RAT Detection and Prevention

NOP Sleds are effective ways to inject RATs and other malware. See the Malware Signatures list in the program to add your own signatures or to lengthen or shorten the NOP Sled.

Implementing the Permissions Setup:

To set up permissions statically:

Linux:

Run the scanner with sudo:

sudo ./mewtwo.rs

Or set the binary with the setuid bit (not generally recommended for security reasons):

sudo chown root:root mewtwo.rs

sudo chmod u+s mewtwo.rs

Windows:

Run the program as Administrator.

Use a task scheduler to run the program with elevated privileges.


Key Improvements in the Rust Version

Memory Safety:

Rust prevents out-of-bounds access with its strong type system and borrow checker, ensuring that all accesses to memory are safe.

No manual memory management is required; Rust handles memory allocation and deallocation automatically.

Stack Canary Check:

The stack canary check is simulated with a direct comparison. While Rust's memory safety features eliminate many classes of vulnerabilities, this check demonstrates how you can still guard against logic errors.

Malware Signature Scanning:

The scan_for_malware function uses the windows iterator to scan memory slices safely. This prevents out-of-bounds access. 
starts_with is used to check if a slice matches the malware signature, making the code concise and readable.

Error Handling:

Rust provides robust error handling via the Result and Option types, ensuring that potential errors are handled explicitly.

No Unsafe Code:

The code avoids using Rust's unsafe keyword, adhering strictly to safe Rust practices.


To run this code, you would need to add sysinfo to your Cargo.toml:

toml
Copy code
[dependencies]
sysinfo = "0.25.1"



Benefits of Using Rust

Memory Safety: Rust's compiler checks for potential memory safety issues at compile time, reducing the likelihood of runtime errors related to memory management. 
Concurrency: Rust provides strong guarantees around data races, making it a safer choice for concurrent programming. 
Performance: Rust's performance is comparable to C and C++ because it provides low-level control over memory and other system resources without sacrificing safety. 
By using Rust, you gain the benefits of a modern systems programming language that combines performance with safety, making it an excellent choice for writing secure and efficient malware scanners or any low-level system software.

Key Features:

Bytecode Decoding and Encoding: The script decodes and encodes bytecode using hex, allowing for easier pattern matching.

RAT Signature Scanning: The script checks for multiple known RAT signatures, including shellcode, infinite loops, NOP sleds, INT3 instructions, and syscall payloads.

Process Memory: Code attempts to open and read the memory of other processes via the /proc/{pid}/mem files. On most Linux systems, reading these files directly is restricted to the process owner (usually root).

How to Compile and Run:
Save the Script:

Save the script as mewtwo.rs.

Compile the Script:

Use rustc to compile the script:

rustc mewtwo.rs -o mewtwo

Run the Script:
sudo ./mewtwo.rs


