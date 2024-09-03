use std::process;

fn check_stack_overflow(canary: u32) {
    if canary != STACK_CANARY {
        println!("Stack overflow detected! Halting execution...");
        process::exit(1); // Terminate the process with a non-zero exit code
    }
}

fn scan_for_malware(memory: &[u8]) -> bool {
    let mut nop_count = 0;
    let memory_size = memory.len();

    for i in 0..memory_size {
        let address = memory.as_ptr() as usize + i;

        if is_whitelisted(address) {
            continue;
        }

        for (j, signature) in MALWARE_SIGNATURES.iter().enumerate() {
            if memory[i..].starts_with(signature) {
                println!(
                    "Malware detected: Signature {} found at memory address {:p}",
                    j, &memory[i]
                );
                process::exit(1); // Terminate the process when malware is detected
            }
        }

        for (k, heuristic) in HEURISTIC_SIGNATURES.iter().enumerate() {
            if memory[i..].starts_with(heuristic) {
                if k == 0 {
                    nop_count += 1;
                    if nop_count > MAX_NOP_COUNT {
                        println!(
                            "Suspicious NOP sled detected at memory address {:p}",
                            &memory[i]
                        );
                        process::exit(1); // Terminate process if too many NOP instructions are detected
                    }
                } else {
                    println!(
                        "Heuristic alert: Suspicious pattern {} found at memory address {:p}",
                        k, &memory[i]
                    );
                    process::exit(1); // Terminate process if a heuristic alert is triggered
                }
            }
        }
    }

    false
}

fn main() {
    // Set up stack canary
    let stack_canary = STACK_CANARY;

    // Example memory space to scan (this would typically be your program or system memory)
    let mut memory_space: [u8; 1024] = [0; 1024];

    // Simulate writing malware signature to memory for detection demonstration
    memory_space[512..522].copy_from_slice(b"\x60\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2"); // Example shellcode

    // Check for stack overflow before scanning
    check_stack_overflow(stack_canary);

    // Scan memory for malware signatures
    if scan_for_malware(&memory_space) {
        println!("Malware detected in memory!");
    } else {
        println!("No malware detected.");
    }

    // Final check for stack overflow after scanning
    check_stack_overflow(stack_canary);
}
