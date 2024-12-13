// keccak_gpu_infinite.rs

use metal::*;
use rand::rngs::OsRng;
use rand::RngCore;
use rayon::prelude::*;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::env;
use std::ffi::c_void;
use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use hex;
use ctrlc;

/// Maximum pattern length in bytes
const MAX_PATTERN_LEN: usize = 10;

/// Constants
const BATCH_SIZE: usize = 65536; // Increased batch size for better GPU utilization

fn main() {
    // Parse pattern from command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <pattern_hex>", args[0]);
        eprintln!("Example: {} 00ABCD", args[0]);
        std::process::exit(1);
    }

    let pattern_hex = &args[1];
    let pattern_bytes = match hex::decode(pattern_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            eprintln!("Invalid hex string for pattern.");
            std::process::exit(1);
        }
    };

    if pattern_bytes.len() > MAX_PATTERN_LEN {
        eprintln!("Pattern too long. Maximum length is {} bytes.", MAX_PATTERN_LEN);
        std::process::exit(1);
    }

    let pattern_len = pattern_bytes.len() as u32;

    // Pad the pattern to MAX_PATTERN_LEN with zeros
    let mut pattern_padded = vec![0u8; MAX_PATTERN_LEN];
    pattern_padded[..pattern_bytes.len()].copy_from_slice(&pattern_bytes);

    // Initialize Metal device
    let device = Device::system_default().expect("No Metal device found.");
    let command_queue = device.new_command_queue();

    // Load the Metal shader library
    let library_path = "libhashAndMatch.metallib"; // Ensure this path is correct
    let library = device.new_library_with_file(library_path)
        .expect(&format!("Failed to load Metal library from {}", library_path));

    // Get the compute function from the library
    let function = library.get_function("keccak256_kernel", None)
        .expect("Failed to find keccak256_kernel function in the Metal library.");

    // Create a compute pipeline state
    let pipeline_state = device.new_compute_pipeline_state_with_function(&function)
        .expect("Failed to create compute pipeline state.");

    // Initialize the Secp256k1 context
    let secp = Secp256k1::new();

    // Initialize the matching vectors (optional, since we print matches immediately)
    // You can remove these if you don't need to keep track of matches within the program
    // let mut matching_keys: Vec<[u8; 32]> = Vec::with_capacity(100);
    // let mut matching_addresses: Vec<[u8; 20]> = Vec::with_capacity(100);

    // Setup for graceful termination
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("\nTermination signal received. Shutting down gracefully...");
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    println!("Starting key generation and pattern matching using GPU...");
    println!("Pattern to match: 0x{}", hex::encode(&pattern_bytes));
    println!("Press Ctrl+C to stop the program.");

    // Start the infinite loop
    let mut batch_count: usize = 0;

    while running.load(Ordering::SeqCst) {
        batch_count += 1;

        // Generate a batch of random private keys (32 bytes each) in parallel
        let private_keys: Vec<SecretKey> = (0..BATCH_SIZE)
            .into_par_iter()
            .map(|_| SecretKey::new(&mut OsRng))
            .collect();

        // Derive corresponding public keys (64 bytes each, uncompressed, without the 0x04 prefix) in parallel
        let public_keys: Vec<[u8; 64]> = private_keys.par_iter()
            .map(|sk| {
                let pk = PublicKey::from_secret_key(&secp, sk);
                let serialized = pk.serialize_uncompressed();
                // Remove the first byte (0x04) and take the next 64 bytes
                let mut pk_bytes = [0u8; 64];
                pk_bytes.copy_from_slice(&serialized[1..65]);
                pk_bytes
            })
            .collect();

        // Flatten the public keys into a single byte vector
        let public_keys_flat: Vec<u8> = public_keys.iter()
            .flat_map(|pk| pk.iter().cloned())
            .collect();

        // Create input buffer for public keys
        let input_buffer = device.new_buffer_with_data(
            public_keys_flat.as_ptr() as *const c_void,
            ((BATCH_SIZE * 64) as usize).try_into().unwrap(),
            MTLResourceOptions::CPUCacheModeDefaultCache
        );

        // Create output buffers
        // Buffer for Keccak-256 hashes (32 bytes per key)
        let output_hash_buffer = device.new_buffer(
            (BATCH_SIZE * 32).try_into().unwrap(),
            MTLResourceOptions::CPUCacheModeDefaultCache
        );

        // Buffer for Ethereum addresses (20 bytes per key)
        let output_eth_address_buffer = device.new_buffer(
            (BATCH_SIZE * 20).try_into().unwrap(),
            MTLResourceOptions::CPUCacheModeDefaultCache
        );

        // Buffer for match flags (1 byte per key)
        let output_match_flag_buffer = device.new_buffer(
            BATCH_SIZE.try_into().unwrap(),
            MTLResourceOptions::CPUCacheModeDefaultCache
        );

        // Buffer for input length (u32, 64 bytes per key)
        // Since each public key is 64 bytes, and all keys have the same length, we can pass the length once
        let input_len: u32 = 64;
        let input_len_buffer = device.new_buffer(
            mem::size_of::<u32>().try_into().unwrap(),
            MTLResourceOptions::CPUCacheModeDefaultCache
        );
        unsafe {
            let len_ptr = input_len_buffer.contents() as *mut u32;
            *len_ptr = input_len;
        }

        // Buffer for pattern data (MAX_PATTERN_LEN bytes)
        let pattern_buffer = device.new_buffer_with_data(
            pattern_padded.as_ptr() as *const c_void,
            MAX_PATTERN_LEN.try_into().unwrap(),
            MTLResourceOptions::CPUCacheModeDefaultCache
        );

        // Buffer for pattern length (u32)
        let pattern_len_buffer = device.new_buffer(
            mem::size_of::<u32>().try_into().unwrap(),
            MTLResourceOptions::CPUCacheModeDefaultCache
        );
        unsafe {
            let plen_ptr = pattern_len_buffer.contents() as *mut u32;
            *plen_ptr = pattern_len;
        }

        // Create a command buffer
        let command_buffer = command_queue.new_command_buffer();

        // Create a compute command encoder
        let compute_encoder = command_buffer.new_compute_command_encoder();

        // Set the compute pipeline state
        compute_encoder.set_compute_pipeline_state(&pipeline_state);

        // Set the buffers in the shader
        compute_encoder.set_buffer(0, Some(&input_buffer), 0);                // Input: Public Keys
        compute_encoder.set_buffer(1, Some(&output_hash_buffer), 0);          // Output: Hashes
        compute_encoder.set_buffer(2, Some(&output_eth_address_buffer), 0);    // Output: Ethereum Addresses
        compute_encoder.set_buffer(3, Some(&output_match_flag_buffer), 0);     // Output: Match Flags
        compute_encoder.set_buffer(4, Some(&input_len_buffer), 0);             // Input Length
        compute_encoder.set_buffer(5, Some(&pattern_buffer), 0);               // Pattern Data
        compute_encoder.set_buffer(6, Some(&pattern_len_buffer), 0);           // Pattern Length

        // Define the number of threads per threadgroup and number of threadgroups
        // Each thread handles one public key
        let threads_per_threadgroup = MTLSize {
            width: 64, // Adjusted to 64 for better utilization based on profiling
            height: 1,
            depth: 1,
        };

        let threadgroups = MTLSize {
            width: ((BATCH_SIZE + threads_per_threadgroup.width as usize - 1) / threads_per_threadgroup.width as usize) as u64,
            height: 1,
            depth: 1,
        };

        // Dispatch threads
        compute_encoder.dispatch_thread_groups(threadgroups, threads_per_threadgroup);

        // End encoding
        compute_encoder.end_encoding();

        // Commit the command buffer
        command_buffer.commit();

        // Wait for the GPU to finish processing
        command_buffer.wait_until_completed();

        // Retrieve the match flags from the output buffer
        let match_flags_ptr = output_match_flag_buffer.contents() as *const u8;
        let match_flags = unsafe { std::slice::from_raw_parts(match_flags_ptr, BATCH_SIZE) };

        // Retrieve the Ethereum addresses from the output buffer
        let eth_addresses_ptr = output_eth_address_buffer.contents() as *const u8;
        let eth_addresses = unsafe { std::slice::from_raw_parts(eth_addresses_ptr, BATCH_SIZE * 20) };

        let start_time = Instant::now();

        // Collect indices of matches
        let matched_indices: Vec<usize> = match_flags.iter()
            .enumerate()
            .filter_map(|(i, &flag)| if flag == 1 { Some(i) } else { None })
            .collect();

        if matched_indices.is_empty() {
            // Optionally, print progress every N batches
            if batch_count % 100 == 0 {
                let elapsed = start_time.elapsed();
                println!("Batch {} processed. Elapsed time: {:.2?}", batch_count, elapsed);
            }
            continue;
        }

        // Process all matches in bulk using Rayon
        let new_matches: Vec<([u8; 32], [u8; 20])> = matched_indices.par_iter().map(|&i| {
            // Extract the corresponding private key
            let private_key = &private_keys[i];
            let private_key_bytes = private_key.secret_bytes();

            // Extract the corresponding Ethereum address
            let addr_start = i * 20;
            let eth_address = &eth_addresses[addr_start..addr_start + 20];
            let eth_address_array: [u8; 20] = eth_address.try_into().expect("Ethereum address length mismatch.");

            (private_key_bytes, eth_address_array)
        }).collect();

        // Print all matches found in this batch
        new_matches.par_iter().for_each(|(key_bytes, addr_bytes)| {
            println!("Match Found:");
            println!("Private Key: 0x{}", hex::encode(key_bytes));
            println!("Ethereum Address: 0x{}", hex::encode(addr_bytes));
            println!("----------------------------------------");
        });

        // Optionally, track the total number of matches
        // Uncomment the following lines if you want to keep a count
        /*
        for (key_bytes, addr_bytes) in &new_matches {
            matching_keys.push(*key_bytes);
            matching_addresses.push(*addr_bytes);
        }
        */

        // Optionally, print batch status
        println!("Batch {} processed. Total Matches Found So Far: {}", batch_count, matched_indices.len());

        // Optional: Introduce a short sleep to prevent overwhelming the GPU (tune as needed)
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    println!("\n=== Program Terminated ===");
    println!("Total Batches Processed: {}", batch_count);
    // If you kept track of matches in vectors, you could print a summary here
    // println!("Total Matches Found: {}", matching_keys.len());
}