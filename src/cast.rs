/* Collection of castings functions */
use crate::consts;

use ark_ff::PrimeField as ArkPF;
use babyjubjub_ark::{Fq, Fr, Point, Signature};
use num::{BigInt, Num};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::io::{self};


pub fn public_key_from_str(key_string_hex: &str) -> io::Result<Point> {
    // Split the hex string into x and y parts
    let (x_string_hex, y_string_hex) = key_string_hex.split_at(64);

    // Parse hex strings into BigUint
    let x_decimal = BigUint::from_str_radix(x_string_hex, 16).unwrap();
    let y_decimal = BigUint::from_str_radix(y_string_hex, 16).unwrap();

    // Convert BigUint to Fq
    let x = Fq::from(x_decimal);
    let y = Fq::from(y_decimal);

    Ok(Point { x, y })
}


pub fn signature_from_str(signature_string_hex: &str) -> Signature {
    // Split the string at indices 64 and 128
    let (x_string_hex, temp) = signature_string_hex.split_at(64);
    let (y_string_hex, s_string_hex) = temp.split_at(64);

    // Parse hex strings into BigUint
    let x_decimal = BigUint::from_str_radix(x_string_hex, 16).unwrap();
    let y_decimal = BigUint::from_str_radix(y_string_hex, 16).unwrap();
    let s_decimal = BigUint::from_str_radix(s_string_hex, 16).unwrap();

    // Convert BigUint to Fq
    let x = Fq::from(x_decimal);
    let y = Fq::from(y_decimal);
    let s = Fr::from(s_decimal);

    let r_b8 = Point { x, y };

    Signature { r_b8, s }
}

pub fn fq_to_hex_string(num: &Fq) -> String {
    // convert to a decimal string
    let num_string = num.to_string();

    // Parse the decimal string into a hex
    let num_decimal = BigUint::parse_bytes(num_string.as_bytes(), 10).unwrap();
    let num_hex_string = format!("{:0>64x}", num_decimal);

    // return the hex string
    num_hex_string
}

pub fn fq_to_dec_string(num: &Fq) -> String {
    // convert to a decimal string
    let num_string = num.to_string();

    // Parse the decimal string into a hex
    let num_decimal = BigUint::parse_bytes(num_string.as_bytes(), 10).unwrap();

    // return the hex string
    num_decimal.to_string()
}

pub fn fr_to_hex_string(num: &Fr) -> String {
    // convert to a decimal string
    let num_string = num.to_string();

    // Parse the decimal string into a hex
    let num_decimal = BigUint::parse_bytes(num_string.as_bytes(), 10).unwrap();
    let num_hex_string = format!("{:0>64x}", num_decimal);

    // return the hex string
    num_hex_string
}

pub fn fr_to_dec_string(num: &Fr) -> String {
    // convert to a decimal string
    let num_string = num.to_string();

    // Parse the decimal string into a hex
    let num_decimal = BigUint::parse_bytes(num_string.as_bytes(), 10).unwrap();

    // return the hex string
    num_decimal.to_string()
}

pub fn hash256_as_string(message: &str) -> String {
    // create hash of the message
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let hashed_message = hasher.finalize();

    //Convert the hash result to a BigInt<4> -> hex string -> fq
    let hashed_message_bigint = hash_to_bigint(&hashed_message[..]);
    let hashed_message_string = hashed_message_bigint.to_str_radix(10);

    hashed_message_string
}

pub fn hex_to_dec(hex_str: &str) -> String {
    let hex_value = if hex_str.starts_with("0x") {
        &hex_str[2..] // Remove the '0x' prefix
    } else {
        hex_str
    };

    BigInt::from_str_radix(hex_value, 16)
        .map(|dec_value| dec_value.to_string())
        .unwrap_or_else(|_| String::from("Invalid hex number"))
}

// Converting bytes to fields
pub fn bytes_to_fields(bs: &[u8]) -> Vec<Fq> {
    // Create a vector to store reversed and split bytes
    let reversed_split_bytes: Vec<Vec<u8>> =
        bs.iter()
            .rev()
            .fold(vec![vec![]], |mut acc: Vec<Vec<u8>>, b| {
                let n = acc.len();

                // Check if the current sub-vector is filled to the desired length
                if acc[n - 1].len() == consts::PACKED_BYTE_LEN {
                    // If filled, create a new sub-vector with the current byte
                    acc.push(vec![*b]);
                    acc
                } else {
                    // If not filled, add the current byte to the existing sub-vector
                    acc[n - 1].push(*b);
                    acc
                }
            });
    
    // Reverse, flatten, and convert each sub-vector of bytes to Fq            
    let packed_fields = reversed_split_bytes
        .iter()
        .map(|bs| bs.iter().rev().copied().collect::<Vec<u8>>())
        .map(|bs| Fq::from_be_bytes_mod_order(&bs))
        .rev()
        .collect::<Vec<Fq>>();

    packed_fields
}

fn hash_to_bigint(hash: &[u8]) -> BigUint {
    // Reverse the bytes because BigUint uses little-endian order
    let reversed_hash: Vec<u8> = hash.iter().rev().cloned().collect();

    // Create a BigUint from the reversed hash bytes
    BigUint::from_bytes_le(&reversed_hash)
}