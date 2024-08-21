Key Features:
Bytecode Decoding and Encoding: The script decodes and encodes bytecode using hex, allowing for easier pattern matching.

RAT Signature Scanning: The script checks for multiple known RAT signatures, including shellcode, infinite loops, NOP sleds, INT3 instructions, and syscall payloads.

CLI Parameters and Directory Traversal: The script supports a command-line interface that allows for full traversal of directories, scanning each file for RATs.

Efficient Directory Scanning: The script recursively scans through directories, analyzing all files it encounters.

How to Compile and Run:
Save the Script:

Save the script as rat_scanner.rs.
Compile the Script:

Use rustc to compile the script:
bash
Copy code
rustc mewtwo.rs -o mewtwo
Run the Script:

Execute the compiled binary, passing the file or directory you want to scan:
bash
Copy code
./mewtwo /path/to/directory
Additional Notes:
Error Handling: The script includes basic error handling to manage file read errors and decoding issues.
Signature Database: You can expand the known_rat_signatures vector with more bytecode patterns relevant to the RATs you are targeting.
Customization: Adjust the encoding/decoding logic as needed for the specific firmware or binary formats you're dealing with.
This Rust script provides a robust way to scan files or directories for hidden RATs by checking for known signatures within bytecode, and it can be easily expanded or integrated with other analysis tools.


DISCLAIMER: This code is meant as a conceptual solution and please review the code in order to address issues on your own system.
