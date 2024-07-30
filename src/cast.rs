/* Collection of castings functions */
use crate::{consts, crypto_structures::babyjubjub, Error};

use ark_ff::PrimeField as ArkPF;
use babyjubjub_ark::{Fq, Fr, Point, Signature};
use num::{BigInt, Num};
use num_bigint::BigUint;

pub fn public_key_from_str(key_string_hex: &str) -> Result<Point, Error> {
    // Catch string errors
    if key_string_hex.len() < 64 {
        return Err("Invalid public key hex string.".into());
    }

    // Split the hex string into x and y parts
    // TODO: Replace `split_at` with `split_at_checked`
    let (x_string_hex, y_string_hex) = key_string_hex.split_at(64);

    // Parse hex strings into BigUint
    let x = babyjubjub::hex_to_fq(x_string_hex)?;
    let y = babyjubjub::hex_to_fq(y_string_hex)?;

    Ok(Point { x, y })
}

pub fn signature_from_str(signature_string_hex: &str) -> Result<Signature, Error> {
    // Catch string errors
    if signature_string_hex.len() < 128 {
        return Err("Invalid signature hex string.".into());
    }

    // Split the string at indices 64 and 128
    // TODO: Replace `split_at` with `split_at_checked`
    let (x_string_hex, temp) = signature_string_hex.split_at(64);
    let (y_string_hex, s_string_hex) = temp.split_at(64);

    // convert hex to Fq
    let x = babyjubjub::hex_to_fq(x_string_hex)?;
    let y = babyjubjub::hex_to_fq(y_string_hex)?;

    // Parse hex strings into BigUint
    let s_decimal = BigUint::from_str_radix(s_string_hex, 16)?;

    // Convert BigUint to Fq
    let s = Fr::from(s_decimal);

    let r_b8 = Point { x, y };

    Ok(Signature { r_b8, s })
}

pub fn hex_to_dec(hex_str: &str) -> Result<String, Error> {
    let hex_value = if hex_str.starts_with("0x") {
        &hex_str[2..] // Remove the '0x' prefix
    } else {
        &*hex_str
    };

    BigInt::from_str_radix(hex_value, 16)
        .map(|dec_value| dec_value.to_string())
        .map_err(|e| format!("{}: {}", "Invalid hex string.", e).into())
}

// Converting bytes to fields
pub fn bytes_to_fields(bs: &[u8]) -> Vec<Fq> {
    // Split `bs` into chunks of length PACKED_BYTE_LEN starting from the end
    // of the slice. Done in reverse for technical reasons.
    let reversed_split_bytes: Vec<Vec<u8>> = bs
        .iter()
        .rev() // Iterate in reverse order starting from the last byte
        .fold(vec![vec![]], |mut byte_chunks: Vec<Vec<u8>>, b| {
            let n = byte_chunks.len();

            // Check if the current byte chunk is full
            if byte_chunks[n - 1].len() == consts::PACKED_BYTE_LEN {
                // ...and if so, start filling a new chunk
                byte_chunks.push(vec![*b]);
            } else {
                // ..and if not, add the current byte to the current chunk
                byte_chunks[n - 1].push(*b);
            }

            byte_chunks
        });

    // Appropriately map the chunks in `reversed_split_bytes` to Fq, making sure
    // that the chunks are considered in the right order and the resulting vector is
    // also in the right order.
    let packed_fields = reversed_split_bytes
        .iter()
        .map(|bs| bs.iter().rev().copied().collect::<Vec<u8>>()) // Reverse chunk bytes
        .map(|bs| Fq::from_be_bytes_mod_order(&bs)) // Map each chunk to Fq
        .rev() // Reverse order of field elements
        .collect::<Vec<Fq>>();

    packed_fields
}

pub fn hash_to_bigint(hash: &[u8]) -> BigUint {
    // Reverse the bytes because BigUint uses little-endian order
    let reversed_hash: Vec<u8> = hash.iter().rev().cloned().collect();

    // Create a BigUint from the reversed hash bytes
    BigUint::from_bytes_le(&reversed_hash)
}
