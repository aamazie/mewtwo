use std::fs::{File, read_dir};
use std::io::{self, Read};
use std::process;
use std::path::Path;

const MALWARE_SIGNATURES: [&[u8]; 5] = [
    b"\x60\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2", // Example shellcode signature
    b"\xeb\xfe",                                     // Infinite loop, common in shellcode
    b"\x90\x90\x90\x90",                              // NOP sled, often used in exploits
    b"\xcc\xcc\xcc\xcc",                              // INT3 instructions, potential breakpoint traps
    b"\x6a\x02\x58\xcd\x80",                          // Syscall payload
];

const BUFFER_SIZE: usize = 1024;
const STACK_CANARY: u32 = 0xDEADC0DE;

fn check_stack_overflow(canary: u32) {
    if canary != STACK_CANARY {
        println!("Stack overflow detected! Halting execution...");
        process::exit(1);
    }
}

fn scan_for_malware(file: &mut File) -> io::Result<bool> {
    let mut buffer = [0u8; BUFFER_SIZE];

    while let Ok(bytes_read) = file.read(&mut buffer) {
        if bytes_read == 0 {
            break;
        }

        for i in 0..bytes_read {
            for (j, signature) in MALWARE_SIGNATURES.iter().enumerate() {
                if i + signature.len() <= bytes_read && buffer[i..i + signature.len()] == *signature {
                    println!("Malware detected: Signature {} found", j);
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

fn is_numeric(s: &str) -> bool {
    s.chars().all(|c| c.is_digit(10))
}

fn main() -> io::Result<()> {
    let proc_path = Path::new("/proc");
    let entries = read_dir(proc_path)?;

    for entry in entries {
        if let Ok(entry) = entry {
            let pid = entry.file_name();
            if let Some(pid_str) = pid.to_str() {
                if is_numeric(pid_str) {
                    let mem_path = format!("/proc/{}/mem", pid_str);
                    if let Ok(mut file) = File::open(mem_path) {
                        if scan_for_malware(&mut file)? {
                            println!("Malware detected in process: {}", pid_str);
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
