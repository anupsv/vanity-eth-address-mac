// src/gpu_operations.rs

use metal::*;
use std::ffi::CString;

/// Loads the Metal library and returns the compiled pipeline state.
///
/// # Arguments
///
/// * `device` - The Metal device.
/// * `library_path` - Path to the compiled Metal library.
/// * `function_name` - Name of the compute function in the shader.
///
/// # Returns
///
/// The compute pipeline state.
pub fn load_metal_pipeline(device: &Device, library_path: &str, function_name: &str) -> ComputePipelineState {
    let library = device.new_library_with_file(library_path)
        .expect(&format!("Failed to load Metal library from {}", library_path));

    let function = library.get_function(function_name, None)
        .expect(&format!("Failed to find Metal function '{}'", function_name));

    device.new_compute_pipeline_state_with_function(&function)
        .expect("Failed to create compute pipeline state")
}

/// Performs Keccak-256 hashing and pattern matching on the GPU.
///
/// # Arguments
///
/// * `device` - The Metal device.
/// * `command_queue` - The command queue for executing commands.
/// * `pipeline_state` - The compute pipeline state.
/// * `public_keys` - A slice of serialized and padded public keys.
/// * `pattern` - The desired vanity pattern.
///
/// # Returns
///
/// A vector of indices corresponding to keypairs whose addresses match the pattern.
pub fn hash_and_match(
    device: &Device,
    command_queue: &CommandQueue,
    pipeline_state: &ComputePipelineState,
    public_keys: &[[u8; 136]],
    pattern: &str
) -> Vec<usize> {
    let batch_size = public_keys.len();

    // Prepare public keys as a contiguous byte array
    let mut public_keys_buffer = Vec::with_capacity(batch_size * 136);
    for pub_key in public_keys {
        public_keys_buffer.extend_from_slice(pub_key);
    }

    // Create Metal buffers
    let public_keys_mtl = device.new_buffer_with_data(
        public_keys_buffer.as_ptr() as *const std::ffi::c_void,
        (batch_size * 136).try_into().unwrap(),
        MTLResourceOptions::CPUCacheModeDefaultCache
    );

    // Pattern buffer
    let pattern_len = pattern.len() as u32;
    let pattern_c = CString::new(pattern).expect("CString::new failed");
    let pattern_bytes = pattern_c.as_bytes_with_nul();

    let pattern_mtl = device.new_buffer_with_data(
        pattern_bytes.as_ptr() as *const std::ffi::c_void,
        pattern_bytes.len().try_into().unwrap(),
        MTLResourceOptions::CPUCacheModeDefaultCache
    );

    // Pattern length buffer
    let pattern_len_bytes = pattern_len.to_ne_bytes();
    let pattern_len_mtl = device.new_buffer_with_data(
        &pattern_len_bytes as *const _ as *const std::ffi::c_void,
        std::mem::size_of::<u32>().try_into().unwrap(),
        MTLResourceOptions::CPUCacheModeDefaultCache
    );

    // Matches buffer
    let matches_buffer = device.new_buffer(
        (batch_size * std::mem::size_of::<bool>()).try_into().unwrap(),
        MTLResourceOptions::CPUCacheModeDefaultCache
    );

    // Addresses buffer
    let addresses_size = batch_size * 40; // 40 characters per address
    let addresses_buffer = device.new_buffer(
        addresses_size.try_into().unwrap(),
        MTLResourceOptions::CPUCacheModeDefaultCache
    );

    // Create a command buffer
    let command_buffer = command_queue.new_command_buffer();

    // Create a compute command encoder
    let compute_encoder = command_buffer.new_compute_command_encoder();

    // Set pipeline state
    compute_encoder.set_compute_pipeline_state(pipeline_state);

    // Set buffers
    compute_encoder.set_buffer(0, Some(&public_keys_mtl), 0);
    compute_encoder.set_buffer(1, Some(&pattern_mtl), 0);
    compute_encoder.set_buffer(2, Some(&pattern_len_mtl), 0);
    compute_encoder.set_buffer(3, Some(&matches_buffer), 0);
    compute_encoder.set_buffer(4, Some(&addresses_buffer), 0); // Set addresses buffer

    // Define threadgroups
    let threads_per_threadgroup = MTLSize {
        width: 256,
        height: 1,
        depth: 1,
    };

    let threadgroups = MTLSize {
        width: ((batch_size + threads_per_threadgroup.width as usize - 1) / threads_per_threadgroup.width as usize) as u64,
        height: 1,
        depth: 1,
    };

    // Dispatch threads
    compute_encoder.dispatch_thread_groups(threadgroups, threads_per_threadgroup);

    // End encoding
    compute_encoder.end_encoding();

    // Commit and wait
    command_buffer.commit();
    command_buffer.wait_until_completed();

    // Retrieve match results
    let matches_ptr = matches_buffer.contents() as *const bool;
    let matches_slice = unsafe { std::slice::from_raw_parts(matches_ptr, batch_size) };

    // Retrieve the addresses from the GPU
    let addresses_ptr = addresses_buffer.contents() as *const u8;
    let addresses_slice = unsafe { std::slice::from_raw_parts(addresses_ptr, addresses_size) };

    // Collect matching indices
    matches_slice.iter()
        .enumerate()
        .filter_map(|(i, &matched)| if matched { Some(i) } else { None })
        .collect()
}