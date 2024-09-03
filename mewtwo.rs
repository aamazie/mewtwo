use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

// Example malware signatures (simplified for demonstration)
const MALWARE_SIGNATURES: [&[u8]; 5] = [
    b"\x60\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2", // Example shellcode signature
    b"\xeb\xfe",                                     // Infinite loop, common in shellcode
    b"\x90\x90\x90\x90",                             // NOP sled, often used in exploits
    b"\xcc\xcc\xcc\xcc",                             // INT3 instructions, potential breakpoint traps
    b"\x6a\x02\x58\xcd\x80",                         // Syscall payload
];

// Function to read a file into memory
fn read_file_to_memory<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

// Function to scan memory for malware signatures
fn scan_for_malware(memory: &[u8]) -> bool {
    for (i, window) in memory.windows(16).enumerate() {
        for (j, signature) in MALWARE_SIGNATURES.iter().enumerate() {
            if window.starts_with(signature) {
                println!(
                    "Malware detected: Signature {} found at memory address {:p}",
                    j, &memory[i]
                );
                return true;  // Malware found
            }
        }
    }
    false  // No malware found
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <filename>", args[0]);
        return;
    }

    let file_path = &args[1];
    let memory = match read_file_to_memory(file_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to read file: {}", e);
            return;
        }
    };

    if scan_for_malware(&memory) {
        println!("Malware detected in file!");
    } else {
        println!("No malware detected in file.");
    }
}
