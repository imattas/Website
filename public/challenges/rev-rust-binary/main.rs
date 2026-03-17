/*
 * CTF Challenge: Rust Binary Reversing
 *
 * Build: cargo build --release
 * Run:   cargo run --release
 *
 * Rust binaries are notoriously difficult to reverse engineer due to:
 *   - Heavy use of iterators (compiled to complex loop structures)
 *   - Option/Result types (lots of unwrap/match code)
 *   - String types (not just char*, involves len + ptr + capacity)
 *   - Mangled symbol names
 *   - Monomorphized generics (duplicated function bodies)
 *
 * To solve:
 *   1. Use Ghidra with the Rust demangling plugin
 *   2. Look for the validation functions by searching for string refs
 *   3. Trace the iterator chains to understand the transforms
 *   4. Extract the expected values and reverse the operations
 *
 * The password goes through multiple stages:
 *   Stage 1: Each char is mapped to its ASCII value
 *   Stage 2: Values are XOR'd with position-dependent key
 *   Stage 3: Results are folded/accumulated with addition
 *   Stage 4: Final comparison against expected checksum per chunk
 *
 * VULNERABILITY: Despite the complex iterator chains, the math is
 * simple XOR + addition. Extract expected values and reverse.
 */

use std::io::{self, Write};

/// XOR key derived from position
/// VULNERABILITY: Simple position-based XOR key
fn position_key(pos: usize) -> u8 {
    let keys: [u8; 8] = [0x13, 0x37, 0x42, 0x69, 0xAA, 0xBB, 0xCC, 0xDD];
    keys[pos % keys.len()]
}

/// Stage 1: Transform input bytes using iterator chain
/// VULNERABILITY: This compiles to a complex loop in the binary,
/// but it's just mapping each byte through XOR with position key
fn stage1_transform(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ position_key(i))
        .collect()
}

/// Stage 2: Validate using Option-based checks
/// VULNERABILITY: Each Option unwrap/match generates lots of assembly
/// but the actual check is simple comparison
fn stage2_validate(transformed: &[u8]) -> Option<bool> {
    /* Expected values after XOR transform
     * These are: "zemi{rust_r3v3rs1ng_p41n}" XOR'd with position keys */
    let expected: Vec<u8> = vec![
        0x69, 0x54, 0x2F, 0x04, 0x91, 0x85, 0xA1, 0xAC,
        0x42, 0x45, 0x7B, 0x06, 0x97, 0x85, 0xFB, 0xB1,
        0x5B, 0x56, 0x2E, 0x04, 0x8B, 0x93, 0xAD, 0xB1,
        0x52
    ];

    if transformed.len() != expected.len() {
        return Some(false);
    }

    let matches = transformed
        .iter()
        .zip(expected.iter())
        .filter(|(&a, &b)| a == b)
        .count();

    Some(matches == expected.len())
}

/// Stage 3: Additional checksum validation using fold
/// VULNERABILITY: Iterator fold/reduce compiles to accumulator loop.
/// The checksum is just sum of all transformed bytes modulo 256.
fn stage3_checksum(transformed: &[u8]) -> bool {
    let checksum: u32 = transformed
        .iter()
        .enumerate()
        .map(|(i, &b)| (b as u32).wrapping_mul((i as u32) + 1))
        .fold(0u32, |acc, x| acc.wrapping_add(x));

    /* Expected checksum for the correct input */
    checksum == 0x0000C5E2
}

/// Multi-stage validation combining all checks
fn validate_flag(input: &str) -> Result<bool, String> {
    let input_bytes = input.as_bytes();

    /* Length check */
    if input_bytes.len() != 25 {
        return Err(format!(
            "Expected 25 characters, got {}",
            input_bytes.len()
        ));
    }

    /* Prefix check using pattern matching */
    match input_bytes {
        [b'z', b'e', b'm', b'i', b'{', .., b'}'] => {}
        _ => return Err("Invalid flag format".to_string()),
    }

    /* Stage 1: Transform */
    let transformed = stage1_transform(input_bytes);

    /* Stage 2: Validate transformed bytes */
    let stage2_result = stage2_validate(&transformed)
        .unwrap_or(false);

    if !stage2_result {
        return Ok(false);
    }

    /* Stage 3: Checksum */
    if !stage3_checksum(&transformed) {
        return Ok(false);
    }

    Ok(true)
}

fn main() {
    println!("=== Rust CrackMe v1.0 ===");
    print!("Enter the flag: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    let input = input.trim();

    match validate_flag(input) {
        Ok(true) => {
            println!("[+] Correct! Flag verified: {}", input);
        }
        Ok(false) => {
            println!("[-] Wrong flag.");
            println!("[-] Hint: Rust iterators are your enemy in the disassembly.");
        }
        Err(e) => {
            println!("[-] Error: {}", e);
        }
    }
}
