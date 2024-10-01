use crate::{cast, consts, crypto_structures::signature, io_utils, serialization, Error};
pub use ark_bn254::Fr as Fq; // Fr (scalar field) of BN254 is the Fq (base field) of Babyjubjub
use ark_std::str::FromStr; // import to use from_str in structs
use babyjubjub_ark::{new_key, Fr, Point, PrivateKey};
use chrono::{DateTime, Utc}; // for date_to_fq
use num::{BigUint, Num};
use poseidon_ark::Poseidon;
pub use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PubKey {
    #[serde(
        serialize_with = "serialization::ark_se",
        deserialize_with = "serialization::ark_de"
    )]
    pub x: Fq,
    #[serde(
        serialize_with = "serialization::ark_se",
        deserialize_with = "serialization::ark_de"
    )]
    pub y: Fq,
}

/// Str hex is simple concatenating the hex of the x and y of the pubkey
impl PubKey {
    pub fn from_str_hex(pubkey_str: String) -> Result<PubKey, Error> {
        // Split the public key string into two parts: pubkey_x_str and pubkey_y_str
        let (x_str, y_str) = io_utils::split_hex_string(pubkey_str.as_str());

        // validate public key input and split it into x and y
        let pubkey = PubKey {
            x: hex_to_fq(&x_str)?,
            y: hex_to_fq(&y_str)?,
        };

        Ok(pubkey)
    }

    pub fn to_fq_vec(&self) -> Vec<Fq> {
        vec![self.x, self.y]
    }

    pub fn from_point(point: Point) -> PubKey {
        let pubkey = PubKey {
            x: point.x,
            y: point.y,
        };

        pubkey
    }

    pub fn to_hex_str(&self) -> String {
        let hex_string_x: String = fq_to_str_hex(&self.x);
        let hex_string_y: String = fq_to_str_hex(&self.y);

        format!("{}{}", hex_string_x, hex_string_y)
    }
} // impl Pubkey

#[derive(Serialize, Deserialize)]
pub struct PrivKey {
    pub key: [u8; 32],
}

impl PrivKey {
    // Generate a new random PrivKey
    pub fn generate() -> PrivKey {
        // Initialize a random number generator
        let mut rng = rand::thread_rng();

        // Generate a new private key
        let privkey = PrivKey {
            key: new_key(&mut rng).key,
        };

        privkey
    }

    // Save the PrivKey to a file
    pub fn save_to_file(&self, file_path: &str) -> Result<(), Error> {
        // Serialize the struct to JSON
        let mut json_data = serde_json::to_string(self)?;

        // Append a newline character to the JSON data
        json_data.push('\n');

        // Create or open the file
        let mut file = File::create(Path::new(file_path))?;

        // Write the JSON data to the file
        file.write_all(json_data.as_bytes())?;

        Ok(())
    }

    // Read the PrivKey from a file
    pub fn read_from_file(file_path: &str) -> Result<PrivKey, Error> {
        // Open the file
        let mut file = File::open(Path::new(file_path))?;

        // Read the file contents into a string
        let mut json_data = String::new();
        file.read_to_string(&mut json_data)?;

        // Deserialize the JSON data to a PrivKey struct
        let privkey: PrivKey = serde_json::from_str(&json_data)?;

        Ok(privkey)
    }

    pub fn to_hex_str(&self) -> String {
        let mut private_key_hex = "".to_string();

        for &num in &self.key {
            let num_hex = format!("{:02x}", num);
            private_key_hex.push_str(&num_hex);
        }

        private_key_hex
    }

    pub fn to_dec_str(&self) -> String {
        let mut private_key_dec = "".to_string();

        for &num in &self.key {
            let num_dec = format!("{:?}", num);
            private_key_dec.push_str(&num_dec);
        }

        private_key_dec
    }

    pub fn public(&self) -> PubKey {
        let babyjubjub_private_key = PrivateKey { key: self.key };

        let babyjubjub_public_key = babyjubjub_private_key.public();

        PubKey {
            x: babyjubjub_public_key.x,
            y: babyjubjub_public_key.y,
        }
    }

    pub fn sign(&self, hash_fq: Fq) -> Result<signature::Signature, Error> {
        let babyjubjub_private_key = PrivateKey { key: self.key };

        // Sign the hash
        let signature_components = babyjubjub_private_key
            .sign(hash_fq)
            .map_err(|e| format!("Failed to sign message: {}", e))?;

        let signature = signature::Signature {
            s: signature_components.s,
            rx: signature_components.r_b8.x,
            ry: signature_components.r_b8.y,
        };

        Ok(signature)
    }
}

// Casting Fr of Babyjubjub to hex strings
pub fn fr_to_str_hex(fr: &Fr) -> String {
    // convert to a decimal string
    let fr_str_dec = fr.to_string();

    // Parse the decimal string into a hex
    let fr_biguint = BigUint::parse_bytes(fr_str_dec.as_bytes(), 10).unwrap();
    let fr_str_hex = format!("{:0>64x}", fr_biguint);

    // return the hex string
    fr_str_hex
}

/* Functions casting to Fq */

/* Existing functions:
*  Fq::from(x), where x is u128/u64/u32/u8/bool or i128/i64/i32/i8,
*  Fq::from_str(s), where s is a string of decimal numbers as a (congruent) prime field element */

pub fn hex_to_fq(hex_string: &str) -> Result<Fq, Error> {
    // Strip '0x' prefix if present
    let hex_str = if hex_string.starts_with("0x") || hex_string.starts_with("0X") {
        &hex_string[2..]
    } else {
        hex_string
    };

    // Convert hex string to BigUint
    let x_decimal = BigUint::from_str_radix(hex_str, 16)?;

    // Convert BigUint to Fq
    let x = Fq::from(x_decimal);

    Ok(x)
}

pub fn evm_address_to_fq(hex_address: &str) -> Result<Fq, Error> {
    let address_dec = cast::hex_to_dec(&hex_address)?;
    let address_fq = Fq::from_str(&*address_dec).unwrap();

    Ok(address_fq)
}

pub fn woolball_name_to_fq(name: &str) -> Result<Fq, Error> {
    // calculate hash
    let mut parts = name.split('.').collect::<Vec<&str>>();

    // Initialize the hash with the rightmost part, which includes the '#'
    let mut current_hash = {
        let last_part = parts
            .pop()
            .expect("Input should contain at least one part ending with '#'");
        sha256(last_part)
    };

    // Iterate from right to left, combining the current part with the hash of the previous step
    while let Some(part) = parts.pop() {
        let combined = format!("{}{}", part, current_hash);
        current_hash = sha256(&combined);
    }

    // uint256 => Fq
    let sha256_fq = message_to_fq_vec(&current_hash)?;

    Ok(sha256_fq)
}

pub fn datetime_utc_to_fq(datetime: DateTime<Utc>) -> Result<Fq, Error> {
    let datetime_i64 = datetime.timestamp();

    Ok(Fq::from(datetime_i64))
}

// String message to vector of Fq
// It creates a Poseidon hash of the message
pub fn message_to_fq_vec(message: &str) -> Result<Fq, Error> {
    // calculate max message length for Poesidon hash
    const MAX_POSEIDON_MESSAGE_LEN: usize =
        consts::MAX_POSEIDON_PERMUTATION_LEN * consts::PACKED_BYTE_LEN;

    if message.len() > MAX_POSEIDON_MESSAGE_LEN {
        Err("Message is too long")?;
    }

    let bytes = message.as_bytes();

    // Pack the message bytes into right-aligned 31-byte chunks
    let fq_vector: Vec<Fq> = cast::bytes_to_fields(bytes)
        .iter()
        .map(|&b| Fq::from_str(&b.to_string()).unwrap())
        .collect();

    // Create a Poseidon hash function
    let poseidon = Poseidon::new();

    // // Hash the input vector
    Ok(poseidon.hash(fq_vector)?)
}

// Casting Fr of Babyjubjub to hex strings
pub fn fq_to_str_hex(fq: &Fq) -> String {
    // convert to a decimal string
    let fq_string = fq.to_string();

    // Parse the decimal string into a hex
    let fq_decimal = BigUint::parse_bytes(fq_string.as_bytes(), 10).unwrap();

    // return the hex string
    format!("{:0>64x}", fq_decimal)
}

pub fn fq_to_dec_str(fq: &Fq) -> String {
    // convert to a decimal string
    let fq_string = fq.to_string();

    // Parse the decimal string into a hex
    let fq_decimal = BigUint::parse_bytes(fq_string.as_bytes(), 10).unwrap();

    // return the hex string
    fq_decimal.to_string()
}

/// Computes the SHA-256 hash of the given message and returns it as a decimal string.
pub fn sha256(message: &str) -> String {
    // create hash of the message
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let hashed_message = hasher.finalize();

    //Convert the hash result to a BigInt<4> -> hex string -> fq
    let hashed_message_bigint = cast::hash_to_bigint(&hashed_message[..]);
    let hashed_message_string = hashed_message_bigint.to_str_radix(10);

    hashed_message_string
}
