// hashAndMatch.metal

#include <metal_stdlib>
using namespace metal;

// === Constants ===

// Round constants (RC) for Keccak-f[1600]
constant ulong ROUND_CONSTANTS[24] = {
    0x0000000000000001ULL,
    0x0000000000008082ULL,
    0x800000000000808aULL,
    0x8000000080008000ULL,
    0x000000000000808bULL,
    0x0000000080000001ULL,
    0x8000000080008081ULL,
    0x8000000000008009ULL,
    0x000000000000008aULL,
    0x0000000000000088ULL,
    0x0000000080008009ULL,
    0x000000008000000aULL,
    0x000000008000808bULL,
    0x800000000000008bULL,
    0x8000000000008089ULL,
    0x8000000000008003ULL,
    0x8000000000008002ULL,
    0x8000000000000080ULL,
    0x000000000000800aULL,
    0x800000008000000aULL,
    0x8000000080008081ULL,
    0x8000000000008080ULL,
    0x0000000080000001ULL,
    0x8000000080008008ULL
};

// === Helper Functions ===

/// Rotate left a 64-bit word by n bits
inline ulong rotl64(ulong x, ulong n) {
    return (x << n) | (x >> (64 - n));
}

/// Keccak-f[1600] permutation
inline void keccak_f1600(thread ulong *state) { // Added 'thread' address space qualifier
    for (int round = 0; round < 24; round++) {
        // === Theta Step ===
        ulong C[5];
        for (int x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        ulong D[5];
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        for (int i = 0; i < 25; i++) {
            state[i] ^= D[i % 5];
        }

        // === Rho and Pi Steps ===
        ulong B[25];
        B[0] = state[0];
        B[1] = rotl64(state[6], 44);
        B[2] = rotl64(state[12], 43);
        B[3] = rotl64(state[18], 21);
        B[4] = rotl64(state[24], 14);
        B[5] = rotl64(state[3], 28);
        B[6] = rotl64(state[9], 20);
        B[7] = rotl64(state[10], 3);
        B[8] = rotl64(state[16], 45);
        B[9] = rotl64(state[22], 61);
        B[10] = rotl64(state[1], 1);
        B[11] = rotl64(state[7], 6);
        B[12] = rotl64(state[13], 25);
        B[13] = rotl64(state[19], 8);
        B[14] = rotl64(state[20], 18);
        B[15] = rotl64(state[4], 27);
        B[16] = rotl64(state[5], 36);
        B[17] = rotl64(state[11], 10);
        B[18] = rotl64(state[17], 15);
        B[19] = rotl64(state[23], 56);
        B[20] = rotl64(state[2], 62);
        B[21] = rotl64(state[8], 55);
        B[22] = rotl64(state[14], 39);
        B[23] = rotl64(state[15], 41);
        B[24] = rotl64(state[21], 2);

        // === Chi Step ===
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                state[x + 5*y] = B[x + 5*y] ^ ((~B[((x + 1) % 5) + 5*y]) & B[((x + 2) % 5) + 5*y]);
            }
        }

        // === Iota Step ===
        state[0] ^= ROUND_CONSTANTS[round];
    }
}

/// Computes the Keccak-256 hash of the input data.
/// 
/// # Arguments
/// 
/// - `input`: Pointer to the input data.
/// - `input_len`: Length of the input data in bytes.
/// - `output`: Pointer to the output buffer (must be at least 32 bytes).
inline void keccak256_hash(device const uint8_t *input, uint input_len, device uint8_t *output) {
    // Initialize state to zero
    thread ulong state[25];
    for (int i = 0; i < 25; i++) {
        state[i] = 0ULL;
    }

    const uint rate = 136; // 136 bytes = 1088 bits (Keccak-256 rate)
    uint8_t buffer[136];
    
    // Initialize buffer to zero
    for (int i = 0; i < 136; i++) {
        buffer[i] = 0;
    }

    uint consumed = 0;
    uint offset = 0;
    while (consumed < input_len) {
        uint to_copy = min(rate - offset, input_len - consumed);
        for (uint i = 0; i < to_copy; i++) {
            buffer[offset + i] = input[consumed + i];
        }
        offset += to_copy;
        consumed += to_copy;

        if (offset == rate) {
            // XOR buffer into state
            for (int i = 0; i < 17; i++) { // 17 * 8 = 136 bytes
                ulong t = 0;
                for (int b = 0; b < 8; b++) {
                    t |= ((ulong)buffer[i * 8 + b]) << (8 * b);
                }
                state[i] ^= t;
            }
            keccak_f1600(state);
            offset = 0;
            // Reset buffer to zero
            for (int i = 0; i < 136; i++) {
                buffer[i] = 0;
            }
        }
    }

    // === Padding (pad10*1) ===
    buffer[offset] = 0x01;
    for (int i = offset + 1; i < rate; i++) {
        buffer[i] = 0x00;
    }
    buffer[rate - 1] |= 0x80; // Set the last byte's MSB to 1

    // XOR the padded buffer into state
    for (int i = 0; i < 17; i++) { // 17 * 8 = 136 bytes
        ulong t = 0;
        for (int b = 0; b < 8; b++) {
            t |= ((ulong)buffer[i * 8 + b]) << (8 * b);
        }
        state[i] ^= t;
    }
    keccak_f1600(state);

    // === Squeezing Phase: Extract the first 32 bytes of the state as the hash ===
    for (int i = 0; i < 32; i++) {
        output[i] = (uint8_t)((state[i / 8] >> (8 * (i % 8))) & 0xFF);
    }
}

/// Extracts the Ethereum address from the Keccak-256 hash.
/// The Ethereum address is the last 20 bytes of the hash.
inline void compute_eth_address(device const uint8_t *hash, device uint8_t *eth_address) {
    // Ethereum address is the last 20 bytes of the Keccak-256 hash
    for (int i = 0; i < 20; i++) {
        eth_address[i] = hash[12 + i]; // bytes 12 to 31
    }
}

/// Pattern matching logic: Check if the Ethereum address starts with the specified pattern.
/// 
/// # Arguments
/// 
/// - `eth_address`: Pointer to the Ethereum address (20 bytes).
/// - `pattern`: Pointer to the pattern data.
/// - `pattern_len`: Length of the pattern in bytes.
/// 
/// # Returns
/// 
/// - `true` if the Ethereum address starts with the pattern, `false` otherwise.
inline bool pattern_match(device const uint8_t *eth_address, device const uint8_t *pattern, uint pattern_len) {
    for (uint i = 0; i < pattern_len; i++) {
        if (eth_address[i] != pattern[i]) {
            return false;
        }
    }
    return true;
}

// === Kernel Function ===

/// Metal kernel to compute Keccak-256 hash, Ethereum address, and perform pattern matching.
/// 
/// # Arguments
/// 
/// - `input`: Buffer containing public keys (64 bytes each).
/// - `output_hash`: Buffer to store the Keccak-256 hashes (32 bytes each).
/// - `output_eth_address`: Buffer to store the Ethereum addresses (20 bytes each).
/// - `output_match_flag`: Buffer to store the match flags (1 byte each).
/// - `input_len`: Length of each public key in bytes (should be 64).
/// - `pattern`: Buffer containing the pattern to match.
/// - `pattern_len`: Length of the pattern in bytes.
/// - `gid`: Thread ID (used to index into the buffers).
kernel void keccak256_kernel(
    device const uint8_t *input [[buffer(0)]],
    device uint8_t *output_hash [[buffer(1)]],
    device uint8_t *output_eth_address [[buffer(2)]],
    device uint8_t *output_match_flag [[buffer(3)]],
    constant uint &input_len [[buffer(4)]],
    device const uint8_t *pattern [[buffer(5)]],
    constant uint &pattern_len [[buffer(6)]],
    uint gid [[thread_position_in_grid]]
) {
    // Each thread processes one public key
    uint key_offset = gid * input_len;
    
    // Pointers to the current public key, hash, address, and match flag
    device const uint8_t *current_key = input + key_offset;
    device uint8_t *current_hash = output_hash + (gid * 32);
    device uint8_t *current_eth_address = output_eth_address + (gid * 20);
    device uint8_t *current_match_flag = output_match_flag + gid;
    
    // Compute Keccak-256 hash
    keccak256_hash(current_key, input_len, current_hash);
    
    // Compute Ethereum address
    compute_eth_address(current_hash, current_eth_address);
    
    // Perform pattern matching
    bool is_match = pattern_match(current_eth_address, pattern, pattern_len);
    
    // Set match flag
    current_match_flag[0] = is_match ? 1 : 0;
}