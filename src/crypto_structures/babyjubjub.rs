use crate::{bn254_scalar_cast, cast, crypto_structures::signature, serialization, Error};
pub use ark_bn254::Fr as BN254R;
use babyjubjub_ark::{new_key, Point, PrivateKey};
pub use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PubKey {
    #[serde(
        serialize_with = "serialization::ark_se",
        deserialize_with = "serialization::ark_de"
    )]
    pub x: BN254R,
    #[serde(
        serialize_with = "serialization::ark_se",
        deserialize_with = "serialization::ark_de"
    )]
    pub y: BN254R,
}

/// Str hex is simple concatenating the hex of the x and y of the pubkey
impl PubKey {
    pub fn from_str_hex(pubkey_str: String) -> PubKey {
        let pubkey_vec = bn254_scalar_cast::babyjubjub_pubkey_to_bn254(&pubkey_str).unwrap();

        // validate public key input and split it into x and y
        PubKey {
            x: pubkey_vec[0],
            y: pubkey_vec[1],
        }
    }

    pub fn to_bn254_r(&self) -> Vec<BN254R> {
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
        let hex_string_x: String = cast::fq_to_hex_string(&self.x);
        let hex_string_y: String = cast::fq_to_hex_string(&self.y);

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

    pub fn sign(&self, hash_bn254: BN254R) -> Result<signature::Signature, Error> {
        let babyjubjub_private_key = PrivateKey { key: self.key };

        // Sign the hash
        let signature_components = babyjubjub_private_key
            .sign(hash_bn254)
            .map_err(|e| format!("Failed to sign message: {}", e))?;

        let signature = signature::Signature {
            s: signature_components.s,
            rx: signature_components.r_b8.x,
            ry: signature_components.r_b8.y,
        };

        Ok(signature)
    }
}
