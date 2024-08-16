use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use hex;

fn decode_bytecode(data: &str) -> Option<Vec<u8>> {
    match hex::decode(data) {
        Ok(decoded) => Some(decoded),
        Err(_) => {
            eprintln!("Error decoding data. It may not be properly encoded.");
            None
        }
    }
}

fn encode_bytecode(data: &[u8]) -> String {
    hex::encode(data)
}

fn scan_for_rats(decoded_data: &[u8]) -> bool {
    let known_rat_signatures = vec![
        b"\x60\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2".to_vec(), // Example shellcode signature
        b"\xeb\xfe".to_vec(), // Infinite loop, common in shellcode
        b"\x90\x90\x90\x90".to_vec(), // NOP sled, often used in exploits
        b"\xcc\xcc\xcc\xcc".to_vec(), // INT3 instructions, potential breakpoint traps
        b"\x6a\x02\x58\xcd\x80".to_vec(), // Syscall payload
    ];

    for sig in known_rat_signatures {
        if decoded_data.windows(sig.len()).any(|window| window == sig) {
            println!(
                "Potential RAT detected: Signature {} found.",
                encode_bytecode(&sig)
            );
            return true;
        }
    }
    println!("No known RAT signatures detected.");
    false
}

fn scan_bytecode(file_path: &Path) -> io::Result<()> {
    let mut file = fs::File::open(file_path)?;
    let mut file_data = Vec::new();
    file.read_to_end(&mut file_data)?;

    let encoded_data = encode_bytecode(&file_data);
    if let Some(decoded_data) = decode_bytecode(&encoded_data) {
        if scan_for_rats(&decoded_data) {
            println!("RAT detected in the bytecode of file: {:?}", file_path);
        } else {
            println!("No RAT detected in the bytecode of file: {:?}", file_path);
        }
    } else {
        println!("Failed to decode the bytecode properly.");
    }

    Ok(())
}

fn traverse_directory(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                traverse_directory(&path)?;
            } else {
                scan_bytecode(&path)?;
            }
        }
    } else {
        scan_bytecode(dir)?;
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <file_or_directory_path>", args[0]);
        return;
    }

    let path = Path::new(&args[1]);
    if let Err(e) = traverse_directory(&path) {
        eprintln!("Error scanning directory: {}", e);
    }
}
