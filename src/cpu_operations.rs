// src/cpu_operations.rs

use rayon::prelude::*;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use rand::rngs::OsRng;

/// Define a thread-local Secp256k1 context to ensure thread safety.
thread_local! {
    static SECP: Secp256k1<secp256k1::All> = Secp256k1::new();
}

/// Generates a batch of private keys and derives their corresponding public keys in parallel.
///
/// # Arguments
///
/// * `batch_size` - The number of keypairs to generate.
///
/// # Returns
///
/// A vector of tuples containing the private key and its corresponding public key.
pub fn generate_keypairs(batch_size: usize) -> Vec<(SecretKey, PublicKey)> {
    (0..batch_size)
        .into_par_iter()
        .map(|_| {
            SECP.with(|secp| {
                let mut rng = OsRng;
                secp.generate_keypair(&mut rng)
            })
        })
        .collect()
}

/// Serializes public keys into uncompressed format with proper padding for Keccak-256 hashing.
///
/// # Arguments
///
/// * `public_keys` - An iterator over references to public keys.
///
/// # Returns
///
/// A vector of byte arrays, each representing a serialized and padded uncompressed public key.
pub fn serialize_public_keys_with_padding<'a, I>(public_keys: I) -> Vec<[u8; 136]>
where
    I: Iterator<Item = &'a PublicKey>,
{
    public_keys.map(|pk| {
        let serialized = pk.serialize_uncompressed();
        let mut bytes = [0u8; 136];
        bytes[..64].copy_from_slice(&serialized[1..]); // Copy the first 64 bytes (remove 0x04)
        
        // Apply Keccak padding: pad10*1
        // Append 0x01, followed by 70 bytes of 0x00, and set the last byte to 0x80
        bytes[64] = 0x01; // Append '1' bit (0x01)
        // bytes[65..135] are already 0x00 due to initialization
        bytes[135] = 0x80; // Set the final '1' bit
        
        bytes
    }).collect()
}

/// Derives the Ethereum address from a public key.
///
/// # Arguments
///
/// * `pub_key` - The public key.
///
/// # Returns
///
/// A 20-byte Ethereum address.
pub fn public_key_to_address(pub_key: &PublicKey) -> [u8; 20] {
    use ethers::utils::keccak256;

    let public_key_bytes = pub_key.serialize_uncompressed();
    let hash = keccak256(&public_key_bytes[1..]); // Remove the first byte (0x04)
    let address = <[u8; 20]>::try_from(&hash[12..]).expect("Hash slice should be 20 bytes");
    address
}