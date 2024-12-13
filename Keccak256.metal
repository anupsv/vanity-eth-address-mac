#include <metal_stdlib>
using namespace metal;

constant uint64_t ROUND_CONSTANTS[24] = {
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

inline uint64_t rotl64(uint64_t x, uint64_t n) {
    return (x << n) | (x >> (64 - n));
}

inline void keccak_f1600(thread uint64_t *state) {
    for (int round = 0; round < 24; round++) {
        // Theta
        uint64_t C[5];
        for (int x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        uint64_t D[5];
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        for (int i = 0; i < 25; i++) {
            state[i] ^= D[i % 5];
        }

        // Rho and Pi
        uint64_t B[25];
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

        // Chi
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                state[x + 5*y] = B[x + 5*y] ^ ((~B[((x+1)%5) + 5*y]) & B[((x+2)%5) + 5*y]);
            }
        }

        // Iota
        state[0] ^= ROUND_CONSTANTS[round];
    }
}

inline void keccak256_hash(device const uint8_t *input, uint input_len, device uint8_t *output) {
    // Keccak-256: rate = 136 bytes, capacity = 1088 bits
    uint64_t state[25];
    for (int i = 0; i < 25; i++) {
        state[i] = 0ULL;
    }

    const uint rate = 136;
    uint8_t buffer[136];

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
            // XOR into state
            for (int i = 0; i < 17; i++) {
                uint64_t t = 0;
                for (int b = 0; b < 8; b++) {
                    t |= ((uint64_t)buffer[i*8+b]) << (8*b);
                }
                state[i] ^= t;
            }
            keccak_f1600(state);
            offset = 0;
        }
    }

    // Pad (pad10*1)
    buffer[offset] = 0x01;
    for (int i = offset+1; i < rate; i++) {
        buffer[i] = 0;
    }
    buffer[rate-1] |= 0x80;

    // Final absorb
    for (int i = 0; i < 17; i++) {
        uint64_t t = 0;
        for (int b = 0; b < 8; b++) {
            t |= ((uint64_t)buffer[i*8+b]) << (8*b);
        }
        state[i] ^= t;
    }
    keccak_f1600(state);

    // Squeeze out 32 bytes
    for (int i = 0; i < 32; i++) {
        output[i] = (uint8_t)((state[i/8] >> (8*(i%8))) & 0xFF);
    }
}

kernel void keccak256_kernel(
    device const uint8_t *input [[buffer(0)]],
    device uint8_t *output [[buffer(1)]],
    constant uint &input_len [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid == 0) {
        keccak256_hash(input, input_len, output);
    }
}