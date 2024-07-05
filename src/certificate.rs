pub use ark_bn254::Fr as BN254R;
use chrono::{DateTime, Utc};

use crate::{bn254_scalar_cast, cast};
use ark_serialize::CanonicalSerialize;
use poseidon_ark::Poseidon;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Enum representing various types of fields that can be used in a certificate.
#[derive(Debug)]
pub enum FieldType {
    Name(String),
    Timestamp(DateTime<Utc>),
    Age(u32),
    BabyjubjubPubkey(BabyjubjubPubkey),
    WoolballName(WoolballName),
    EVMAddress(String),
}

/// Enum representing the names of the various field types.
#[derive(Debug, Serialize)]
pub enum FieldTypeName {
    Name,
    Timestamp,
    Age,
    BabyjubjubPubkey,
    WoolballName,
    EVMAddress,
}

/// Struct representing a field in a Format with a name and a type.
#[derive(Debug, Serialize)]
pub struct FormatField {
    /// The name of the field.
    pub fname: String,
    /// The description of the field
    pub fdescription: String,
    /// The type of the field.
    pub ftype: FieldTypeName,
}

/// Struct representing the format of a certificate with fields for the recipient and the body.
pub struct CertFormat {
    /// A vector of format for the recipient, usually it's a format of an ID.
    pub to: Vec<FormatField>,
    /// A vector of format for the body.
    pub body: Vec<FormatField>,
}

/// Struct representing a field within a certificate.
#[derive(Debug)]
pub struct CertField {
    /// The name of the field.
    pub metadata: FormatField,
    /// The value of the field.
    pub field: FieldType,
}

/// Struct representing a certificate with recipient fields,
/// body fields, and an expiration time.
#[derive(Debug)]
pub struct Cert {
    /// A vector of certificate fields for the recipient.
    pub to: Vec<CertField>,
    /// A vector of certificate fields for the body.
    pub body: Vec<CertField>,
    /// The expiration time of the certificate.
    pub expiration: DateTime<Utc>,
}

impl Cert {
    pub fn poseidon_hash(&self) -> BN254R {
        let poseidon_ark = Poseidon::new();
        let hash_fq = poseidon_ark.hash(self.to_bn254r_vector()).unwrap();

        hash_fq
    }

    fn to_bn254r_vector(&self) -> Vec<BN254R> {
        let mut cert_vec: Vec<BN254R> = vec![];

        for cert_field in &self.to {
            let field = &cert_field.field;
            println!("field: {:?}", field);
            match field {
                FieldType::WoolballName(ref woolball_name) => {
                    let woolball_name_bn254r =
                        bn254_scalar_cast::woolball_name_to_bn254(&woolball_name.name).unwrap();

                    let mut woolball_name_254r_vec = vec![woolball_name_bn254r];

                    cert_vec.append(&mut woolball_name_254r_vec);
                }
                FieldType::BabyjubjubPubkey(ref babyjubjub_pubkey) => {
                    let mut babyjubjub_pubkey_vec = babyjubjub_pubkey.to_BN254R();

                    cert_vec.append(&mut babyjubjub_pubkey_vec);
                }

                FieldType::EVMAddress(ref evm_address) => {
                    let evm_address_bn254 =
                        bn254_scalar_cast::EVM_address_to_bn254(&evm_address).unwrap();

                    cert_vec.push(evm_address_bn254);
                }

                _ => {
                    println!("what what what?");
                }
            }
        }

        for cert_field in &self.body {
            let field = &cert_field.field;
            match field {
                FieldType::WoolballName(ref woolball_name) => {
                    let woolball_name_bn254r =
                        bn254_scalar_cast::woolball_name_to_bn254(&woolball_name.name).unwrap();

                    let mut woolball_name_254r_vec = vec![woolball_name_bn254r];

                    cert_vec.append(&mut woolball_name_254r_vec);
                }
                FieldType::BabyjubjubPubkey(ref babyjubjub_pubkey) => {
                    let mut babyjubjub_pubkey_vec = babyjubjub_pubkey.to_BN254R();

                    cert_vec.append(&mut babyjubjub_pubkey_vec);
                }
                FieldType::EVMAddress(ref evm_address) => {
                    let evm_address_bn254 =
                        bn254_scalar_cast::EVM_address_to_bn254(&evm_address).unwrap();

                    cert_vec.push(evm_address_bn254);
                }
                FieldType::Timestamp(ref timestamp) => {
                    let timestamp_bn254r =
                        bn254_scalar_cast::datetime_utc_to_bn254(*timestamp).unwrap();

                    let timestamp_254r_vec = timestamp_bn254r;

                    cert_vec.push(timestamp_254r_vec);
                }

                _ => {
                    println!("what what what?");
                }
            }
        }

        let expiratio_bn254r = bn254_scalar_cast::datetime_utc_to_bn254(self.expiration).unwrap();

        let mut expiration_bn254r_vec = vec![expiratio_bn254r];

        cert_vec.append(&mut expiration_bn254r_vec);

        cert_vec
    }

    pub fn ID(&self) -> String {
        // Concatenate the data from the `to` field
        let mut data = String::new();
        for cert_field in &self.to {
            data.push_str(&format!(
                "{:?}{:?}",
                cert_field.metadata.fname, cert_field.field
            ));
        }

        // Hash the concatenated data
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        let hash = hasher.finalize();

        //Convert the hash result to a BigInt<4> -> hex string -> fq
        let hashed_message_bigint = cast::hash_to_bigint(&hash[..]);
        let hashed_message_string = hashed_message_bigint.to_str_radix(10);

        hashed_message_string
    }
}

#[derive(Debug, CanonicalSerialize)]
pub struct WoolballName {
    pub name: String,
}

impl WoolballName {
    pub fn ID(&self) -> BN254R {
        bn254_scalar_cast::woolball_name_to_bn254(&self.name).unwrap()
    }

    pub fn to_bn254r_vec(&self) -> Vec<BN254R> {
        vec![self.ID()]
    }
}

#[derive(Debug)]
pub struct BabyjubjubPubkey {
    pub x: BN254R,
    pub y: BN254R,
}

/// Str hex is simple concatenating the hex of the x and y of the pubkey
impl BabyjubjubPubkey {
    pub fn from_str_hex(pubkey_str: String) -> BabyjubjubPubkey {
        let pubkey_vec = bn254_scalar_cast::babyjubjub_pubkey_to_bn254(&pubkey_str).unwrap();

        // validate public key input and split it into x and y
        BabyjubjubPubkey {
            x: pubkey_vec[0],
            y: pubkey_vec[1],
        }
    }

    pub fn to_BN254R(&self) -> Vec<BN254R> {
        vec![self.x, self.y]
    }

    pub fn to_str_hex(&self) -> String {
        let hex_string_x: String = cast::fq_to_hex_string(&self.x);
        let hex_string_y: String = cast::fq_to_hex_string(&self.y);

        format!("{}{}", hex_string_x, hex_string_y)
    }
}
