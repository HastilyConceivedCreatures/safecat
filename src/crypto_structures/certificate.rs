pub use ark_bn254::Fr as Fq;
use chrono::{DateTime, Utc};

use crate::{cast, crypto_structures::babyjubjub};
use chrono::NaiveDate;
use inquire::{formatter::DEFAULT_DATE_FORMATTER, CustomType, Text};
use poseidon_ark::Poseidon;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Represents various types of fields that can be used in a certificate.
#[derive(Debug, Serialize, Deserialize)]
pub enum FieldType {
    Name(String),
    Timestamp(DateTime<Utc>),
    Age(u32),
    BabyjubjubPubkey(babyjubjub::PubKey),
    WoolballName(WoolballName),
    EVMAddress(String),
}

/// Represents the names of the various FieldType without holding any data.
/// This enum is useful for defining field types in formats without specifying values.
/// Make sure that this enum stays synchronized with FieldType to avoid mismatches.
#[derive(Debug, Serialize, Deserialize)]
pub enum FieldTypeName {
    Timestamp,
    Age,
    BabyjubjubPubkey,
    WoolballName,
    EVMAddress,
}

/// Represents a field in a Format with a name, description and type.
#[derive(Debug, Serialize, Deserialize)]
pub struct FormatField {
    /// The name of the field.
    pub fname: String,
    /// The description of the field
    pub fdescription: String,
    /// The type of the field.
    pub ftype: FieldTypeName,
}

/// Represents the format of a certificate with fields for the recipient and the body.
#[derive(Debug, Serialize, Deserialize)]
pub struct CertFormat {
    /// A vector of format for the recipient, usually it's a format of an ID.
    pub to: Vec<FormatField>,
    /// A vector of format for the body.
    pub body: Vec<FormatField>,
}

/// Represents a field within a certificate.
#[derive(Debug, Serialize, Deserialize)]
pub struct CertField {
    /// Name, description and type of the field.
    pub format_field: FormatField,
    /// The value of the field.
    pub field: FieldType,
}

/// Represents a certificate with recipient fields, and body fields
#[derive(Debug, Serialize, Deserialize)]
pub struct Cert {
    /// Certificate name (e.g., ID, DAO_membership, etc.)
    pub cert_type: String,
    /// A vector of certificate fields for the recipient.
    pub to: Vec<CertField>,
    /// A vector of certificate fields for the body.
    pub body: Vec<CertField>,
}

impl Cert {
    pub fn poseidon_hash(&self) -> Fq {
        let poseidon_ark = Poseidon::new();

        let hash_fq = poseidon_ark.hash(self.to_fq_vector()).unwrap();

        hash_fq
    }

    // Represent a certificate as a vector for Fq elements. It makes it easier to work with in snarks
    fn to_fq_vector(&self) -> Vec<Fq> {
        let mut cert_vec: Vec<Fq> = vec![];

        cert_vec.push(babyjubjub::message_to_fq_vec(&self.cert_type).unwrap());

        for cert_field in &self.to {
            let field = &cert_field.field;
            match field {
                FieldType::WoolballName(ref woolball_name) => {
                    cert_vec.append(&mut woolball_name.to_fq_vec());
                }
                FieldType::BabyjubjubPubkey(ref babyjubjub_pubkey) => {
                    let mut babyjubjub_pubkey_vec = babyjubjub_pubkey.to_fq_vec();

                    cert_vec.append(&mut babyjubjub_pubkey_vec);
                }

                FieldType::EVMAddress(ref evm_address) => {
                    let evm_address_bn254 =
                        babyjubjub::evm_address_to_fq(&evm_address).unwrap();

                    cert_vec.push(evm_address_bn254);
                }

                _ => {
                    println!("what what is field: {:?}", field);
                }
            }
        }

        for cert_field in &self.body {
            let field = &cert_field.field;
            match field {
                FieldType::WoolballName(ref woolball_name) => {
                    cert_vec.append(&mut woolball_name.to_fq_vec());
                }
                FieldType::BabyjubjubPubkey(ref babyjubjub_pubkey) => {
                    let mut babyjubjub_pubkey_vec = babyjubjub_pubkey.to_fq_vec();

                    cert_vec.append(&mut babyjubjub_pubkey_vec);
                }
                FieldType::EVMAddress(ref evm_address) => {
                    let evm_address_bn254 =
                    babyjubjub::evm_address_to_fq(&evm_address).unwrap();

                    cert_vec.push(evm_address_bn254);
                }
                FieldType::Timestamp(ref timestamp) => {
                    let timestamp_fq =
                        babyjubjub::datetime_utc_to_fq(*timestamp).unwrap();

                    cert_vec.push(timestamp_fq);
                }
                FieldType::Age(ref age) => {
                    let age_fq = Fq::from(*age);

                    cert_vec.push(age_fq);
                }

                _ => {
                    println!("what what is field: {:?}", field);
                }
            }
        }

        cert_vec
    }

    pub fn name(&self) -> String {
        // Concatenate the data from the `to` field
        let mut data = String::new();
        for cert_field in &self.to {
            data.push_str(&format!(
                "{:?}{:?}",
                cert_field.format_field.fname, cert_field.field
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

#[derive(Debug, Serialize, Deserialize)]
pub struct WoolballName {
    pub name: String,
}

impl WoolballName {
    pub fn id(&self) -> Fq {
        babyjubjub::woolball_name_to_fq(&self.name).unwrap()
    }

    pub fn to_fq_vec(&self) -> Vec<Fq> {
        vec![self.id()]
    }
}

pub fn insert_cert_data(format: CertFormat, cert_type: &str) -> Cert {
    let mut cert = Cert {
        cert_type: cert_type.to_string(),
        to: vec![],
        body: vec![],
    };

    for field in format.to {
        match field.ftype {
            FieldTypeName::WoolballName => {
                let name = Text::new(&field.fdescription).prompt().unwrap();
                let woolball_name = WoolballName { name };
                let cert_field = CertField {
                    format_field: field,
                    field: FieldType::WoolballName(woolball_name),
                };

                cert.to.push(cert_field);
            }
            FieldTypeName::BabyjubjubPubkey => {
                // Promptfor pubkey
                let pubkey_hex_str = Text::new(&field.fdescription).prompt().unwrap();

                // // Cast pubkey from hex string to vec of BN245R
                // let pubkey_vec =
                //     bn254_scalar_cast::babyjubjub_pubkey_to_bn254(&pubkey_hex_str).unwrap();

                // validate public key input and split it into x and y
                let babyjubjub_pubkey: babyjubjub::PubKey = babyjubjub::PubKey::from_str_hex(pubkey_hex_str).unwrap();

                let cert_field = CertField {
                    format_field: field,
                    field: FieldType::BabyjubjubPubkey(babyjubjub_pubkey),
                };

                cert.to.push(cert_field);
            }
            FieldTypeName::EVMAddress => {
                let address_hex_str = Text::new(&field.fdescription).prompt().unwrap();

                let cert_field = CertField {
                    format_field: field,
                    field: FieldType::EVMAddress(address_hex_str),
                };

                cert.to.push(cert_field);
            }
            _ => {
                println!("");
            }
        }
    }

    for field in format.body {
        match field.ftype {
            FieldTypeName::WoolballName => {
                let name: String = Text::new(&field.fdescription).prompt().unwrap();
                let cert_field = CertField {
                    format_field: field,
                    field: FieldType::Name(name),
                };

                cert.body.push(cert_field);
            }
            FieldTypeName::BabyjubjubPubkey => {
                // Prompt for pubkey
                let pubkey_hex_str = Text::new(&field.fdescription).prompt().unwrap();

                // Create BabyjubjubPubkey from hex string
                let babyjubjub_pubkey: babyjubjub::PubKey =
                    babyjubjub::PubKey::from_str_hex(pubkey_hex_str).unwrap();

                // create certificate field
                let cert_field = CertField {
                    format_field: field,
                    field: FieldType::BabyjubjubPubkey(babyjubjub_pubkey),
                };

                cert.body.push(cert_field);
            }
            FieldTypeName::Timestamp => {
                let datetime_utc: DateTime<Utc> = CustomType::<NaiveDate>::new(&field.fdescription)
                    .with_placeholder("dd/mm/yyyy")
                    .with_parser(&|i| NaiveDate::parse_from_str(i, "%d/%m/%Y").map_err(|_e| ()))
                    .with_formatter(DEFAULT_DATE_FORMATTER)
                    .with_error_message("Please type a valid date.")
                    .prompt()
                    .unwrap()
                    .and_hms_opt(23, 59, 59)
                    .unwrap()
                    .and_utc();

                // create certificate field
                let cert_field = CertField {
                    format_field: field,
                    field: FieldType::Timestamp(datetime_utc),
                };

                cert.body.push(cert_field);
            }
            FieldTypeName::Age => {
                // Prompt for age
                let age_str = Text::new(&field.fdescription).prompt();

                match age_str {
                    Ok(age_str) => match age_str.parse::<u32>() {
                        Ok(age) if age <= 120 => {
                            let cert_field = CertField {
                                format_field: field,
                                field: FieldType::Age(age),
                            };

                            cert.body.push(cert_field);
                        }
                        Ok(_) => println!("Please enter a valid age between 0 and 120."),
                        Err(_) => println!("Bad age, bad bad!"),
                    },
                    Err(_) => println!("Bad age, bad bad!"),
                }
            }
            _ => {
                println!("");
            }
        }
    }

    cert
}

impl FieldType {
    pub fn is_name(&self) -> bool {
        matches!(self, FieldType::Name(_))
    }

    pub fn as_name(&self) -> Option<&String> {
        if let FieldType::Name(name) = self {
            Some(name)
        } else {
            None
        }
    }

    pub fn is_timestamp(&self) -> bool {
        matches!(self, FieldType::Timestamp(_))
    }

    pub fn as_timestamp(&self) -> Option<&DateTime<Utc>> {
        if let FieldType::Timestamp(timestamp) = self {
            Some(timestamp)
        } else {
            None
        }
    }

    pub fn is_age(&self) -> bool {
        matches!(self, FieldType::Age(_))
    }

    pub fn as_age(&self) -> Option<u32> {
        if let FieldType::Age(age) = self {
            Some(*age)
        } else {
            None
        }
    }

    pub fn is_babyjubjub_pubkey(&self) -> bool {
        matches!(self, FieldType::BabyjubjubPubkey(_))
    }

    pub fn as_babyjubjub_pubkey(&self) -> Option<&babyjubjub::PubKey> {
        if let FieldType::BabyjubjubPubkey(pubkey) = self {
            Some(pubkey)
        } else {
            None
        }
    }

    pub fn is_woolball_name(&self) -> bool {
        matches!(self, FieldType::WoolballName(_))
    }

    pub fn as_woolball_name(&self) -> Option<&WoolballName> {
        if let FieldType::WoolballName(woolball_name) = self {
            Some(woolball_name)
        } else {
            None
        }
    }

    pub fn is_evm_address(&self) -> bool {
        matches!(self, FieldType::EVMAddress(_))
    }

    pub fn as_evm_address(&self) -> Option<&String> {
        if let FieldType::EVMAddress(evm_address) = self {
            Some(evm_address)
        } else {
            None
        }
    }
}
