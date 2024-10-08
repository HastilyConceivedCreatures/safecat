use crate::{
    commands,
    crypto_structures::{babyjubjub, proof_input, signature, woolball::WoolballName},
    serialization,
};
pub use ark_bn254::Fr as Fq;
use chrono::NaiveDate;
use chrono::{DateTime, Utc};
use inquire::{formatter::DEFAULT_DATE_FORMATTER, CustomType, Text};
use serde::{Deserialize, Serialize};
use toml::map::Map;
use toml::Value;

/// Represents different field types that can be used in documents.
#[derive(Debug, Serialize, Deserialize)]
pub enum FieldType {
    Text(String),                         // Plain text
    Integer(u32),                         // Integer values
    Timestamp(DateTime<Utc>),             // Timestamps in UTC format
    Age(u32),                             // Age in years
    BabyjubjubPubkey(babyjubjub::PubKey), // BabyJubJub public key
    WoolballName(WoolballName),           // Woolball name identifier
    EVMAddress(String),                   // Ethereum wallet address
    Signature(signature::Signature),      // Cryptographic signature
    #[serde(
        serialize_with = "serialization::ark_se",
        deserialize_with = "serialization::ark_de"
    )]
    Hash(babyjubjub::Fq), // Hash field
    #[serde(
        serialize_with = "serialization::ark_se",
        deserialize_with = "serialization::ark_de"
    )]
    SignedText(String), // Text that requires a digital signature
    HashPath(proof_input::HashPath),
}

/// Enum for field type names, used to define the type of a field without holding values.
/// Make sure that this enum stays synchronized with FieldType to avoid mismatches.
#[derive(Debug, Serialize, Deserialize)]
pub enum FieldTypeName {
    Text,
    Integer,
    Timestamp,
    Age,
    BabyjubjubPubkey,
    WoolballName,
    EVMAddress,
    Signature,
    Hash,
    SignedText,
    HashPath,
}

/// Defines a field format with a name, description, and its type.
#[derive(Debug, Serialize, Deserialize)]
pub struct FormatField {
    /// The name of the field.
    pub fname: String,
    /// The description of the field
    pub fdescription: String,
    /// The type of the field.
    pub ftype: FieldTypeName,
}

/// Represents a field with its format and actual value in a document.
#[derive(Debug, Serialize, Deserialize)]
pub struct DocumentField {
    /// Name, description and type of the field.
    pub format_field: FormatField,
    /// The value of the field.
    pub field: FieldType,
}

/// Defines a format structure containing multiple fields.
#[derive(Debug, Serialize, Deserialize)]
pub struct Format {
    pub fields: Vec<FormatField>,
}

/// Represents a document structure with its fields.
#[derive(Debug, Serialize, Deserialize)]
pub struct Document {
    pub document_fields: Vec<DocumentField>,
}

impl Document {
    /// Converts the document fields into a vector of `Fq` elements.
    // TODO: change to iter-flat_map-collect method
    pub fn to_fq_vector(&self) -> Vec<Fq> {
        let mut document_vec: Vec<Fq> = vec![];

        // Iterate through document fields and convert each field type to `Fq`
        for document_field in &self.document_fields {
            let field = &document_field.field;
            match field {
                FieldType::Text(ref text) => {
                    let text_bn254 = babyjubjub::message_to_fq_vec(&text).unwrap();

                    document_vec.push(text_bn254);
                }

                FieldType::Integer(ref number) => {
                    let number_bn254 = Fq::from(*number);

                    document_vec.push(number_bn254);
                }

                FieldType::Timestamp(ref timestamp) => {
                    let timestamp_fq = babyjubjub::datetime_utc_to_fq(*timestamp).unwrap();

                    document_vec.push(timestamp_fq);
                }

                FieldType::Age(ref age) => {
                    let age_fq = Fq::from(*age);

                    document_vec.push(age_fq);
                }

                FieldType::BabyjubjubPubkey(ref babyjubjub_pubkey) => {
                    let mut babyjubjub_pubkey_vec = babyjubjub_pubkey.to_fq_vec();

                    document_vec.append(&mut babyjubjub_pubkey_vec);
                }

                FieldType::WoolballName(ref woolball_name) => {
                    document_vec.append(&mut woolball_name.to_fq_vec());
                }

                FieldType::EVMAddress(ref evm_address) => {
                    let evm_address_bn254 = babyjubjub::evm_address_to_fq(&evm_address).unwrap();

                    document_vec.push(evm_address_bn254);
                }

                FieldType::Signature(ref signature) => {
                    let mut signature_vec = signature.to_fq_vec();

                    document_vec.append(&mut signature_vec);
                }

                FieldType::Hash(ref hash) => {
                    document_vec.push(*hash);
                }

                FieldType::SignedText(ref text) => {
                    // Hash and sign text
                    let (signature, hash_fq) =
                        commands::sign::sign_message((*text).clone()).unwrap();

                    // push text's hash
                    document_vec.push(hash_fq);

                    // push signature
                    let mut signature_vec = signature.to_fq_vec();
                    document_vec.append(&mut signature_vec);
                }

                FieldType::HashPath(ref hash_path) => {
                    // Convert the index to Fq and push to the document_vec
                    let index_fq = Fq::from(hash_path.index);
                    document_vec.push(index_fq);

                    // Convert each element in the path (Vec<String>) to Fq and push to the document_vec
                    for path_element in &hash_path.path {
                        let path_element_fq = babyjubjub::message_to_fq_vec(path_element).unwrap();
                        document_vec.push(path_element_fq);
                    }
                }
            }
        }

        document_vec
    }

    /// Converts the document fields to a TOML table.
    /// Values are represented as Fq elements since it's meant be used in Noir.
    pub fn to_toml_table(&self) -> Map<String, Value> {
        // Create an empty TOML table
        let mut toml_table = Map::new();

        // Convert fields to TOML key-value pairs
        for document_field in &self.document_fields {
            match &document_field.field {
                // TODO: Maybe we should hash text before adding it?
                FieldType::Text(value) => {
                    toml_table.insert(
                        document_field.format_field.fname.clone(),
                        Value::String(value.clone()),
                    );
                }
                FieldType::Integer(value) => {
                    toml_table.insert(
                        document_field.format_field.fname.clone(),
                        Value::Integer(*value as i64),
                    );
                }

                FieldType::Timestamp(timestamp) => {
                    toml_table.insert(
                        document_field.format_field.fname.clone(),
                        Value::String(timestamp.timestamp().to_string()),
                    );
                }

                FieldType::Age(value) => {
                    toml_table.insert(
                        document_field.format_field.fname.clone(),
                        Value::Integer(*value as i64),
                    );
                }

                FieldType::BabyjubjubPubkey(pubkey) => {
                    // Serialize BabyjubjubPubkey as a nested TOML table
                    let person_toml = PubKeyString {
                        x: pubkey.x.to_string(),
                        y: pubkey.y.to_string(),
                    };

                    // Create a sub-table for BabyjubjubPubkey
                    let mut sub_table = Map::new();
                    sub_table.insert("x".to_string(), Value::String(person_toml.x));
                    sub_table.insert("y".to_string(), Value::String(person_toml.y));

                    toml_table.insert(
                        document_field.format_field.fname.clone(),
                        Value::Table(sub_table),
                    );
                }

                FieldType::WoolballName(woolball) => {
                    toml_table.insert(
                        document_field.format_field.fname.clone(),
                        Value::String(woolball.id().to_string()),
                    );
                }

                FieldType::EVMAddress(value) => {
                    toml_table.insert(
                        document_field.format_field.fname.clone(),
                        Value::String(value.clone()),
                    );
                }

                FieldType::Signature(signature) => {
                    // Serialize Signature as a nested TOML table
                    let signature_toml = SignatureString {
                        s: signature.s.to_string(),
                        rx: signature.rx.to_string(),
                        ry: signature.ry.to_string(),
                    };

                    // Create a sub-table for Signature
                    let mut sub_table = Map::new();
                    sub_table.insert("s".to_string(), Value::String(signature_toml.s));
                    sub_table.insert("rx".to_string(), Value::String(signature_toml.rx));
                    sub_table.insert("ry".to_string(), Value::String(signature_toml.ry));

                    toml_table.insert(
                        document_field.format_field.fname.clone(),
                        Value::Table(sub_table),
                    );
                }

                FieldType::Hash(hash) => {
                    toml_table.insert(
                        document_field.format_field.fname.clone(),
                        Value::String(hash.to_string()),
                    );
                }

                FieldType::SignedText(text) => {
                    // Hash and sign text
                    let (signature, hash_fq) =
                        commands::sign::sign_message((*text).clone()).unwrap();

                    let signature_message = SignatureMessageString {
                        hash: hash_fq.to_string(),
                        s: signature.s.to_string(),
                        rx: signature.rx.to_string(),
                        ry: signature.ry.to_string(),
                    };

                    // Create a sub-table for Hash and Signature
                    let mut sub_table = Map::new();
                    sub_table.insert("hash".to_string(), Value::String(signature_message.hash));
                    sub_table.insert("s".to_string(), Value::String(signature_message.s));
                    sub_table.insert("rx".to_string(), Value::String(signature_message.rx));
                    sub_table.insert("ry".to_string(), Value::String(signature_message.ry));

                    toml_table.insert(
                        document_field.format_field.fname.clone(),
                        Value::Table(sub_table),
                    );
                }

                FieldType::HashPath(hash_path) => {
                    // Create a sub-table for HashPath
                    let mut sub_table = Map::new();

                    // Insert index
                    sub_table.insert("index".to_string(), Value::Integer(hash_path.index as i64));

                    // Insert path (Vec<String>)
                    let path_values: Vec<Value> = hash_path
                        .path
                        .iter()
                        .map(|p| Value::String(p.clone()))
                        .collect();
                    sub_table.insert("path".to_string(), Value::Array(path_values));

                    toml_table.insert(
                        document_field.format_field.fname.clone(),
                        Value::Table(sub_table),
                    );
                }
            }
        }

        toml_table
    }
}

/// Processes the user input for a given field type and creates a `DocumentField`.
pub fn process_document_field(field: FormatField) -> DocumentField {
    match field.ftype {
        FieldTypeName::Text => {
            let text: String = Text::new(&field.fdescription).prompt().unwrap();
            DocumentField {
                format_field: field,
                field: FieldType::Text(text),
            }
        }

        FieldTypeName::Integer => {
            let int_str = Text::new(&field.fdescription)
                .prompt()
                .expect("Failed to prompt for input");
            let int = int_str
                .parse::<u32>()
                .expect("Failed to parse input as u32");
            DocumentField {
                format_field: field,
                field: FieldType::Integer(int),
            }
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
            DocumentField {
                format_field: field,
                field: FieldType::Timestamp(datetime_utc),
            }
        }

        FieldTypeName::Age => {
            let age_str = Text::new(&field.fdescription).prompt();
            match age_str {
                Ok(age_str) => match age_str.parse::<u32>() {
                    Ok(age) if age <= 120 => DocumentField {
                        format_field: field,
                        field: FieldType::Age(age),
                    },
                    Ok(_) => panic!("Please enter a valid age between 0 and 120."),
                    Err(_) => panic!("Invalid age format."),
                },
                Err(_) => panic!("Error reading age."),
            }
        }

        FieldTypeName::BabyjubjubPubkey => {
            let pubkey_hex_str = Text::new(&field.fdescription).prompt().unwrap();
            let babyjubjub_pubkey: babyjubjub::PubKey =
                babyjubjub::PubKey::from_str_hex(pubkey_hex_str).unwrap();
            DocumentField {
                format_field: field,
                field: FieldType::BabyjubjubPubkey(babyjubjub_pubkey),
            }
        }

        FieldTypeName::WoolballName => {
            let name = Text::new(&field.fdescription).prompt().unwrap();
            let woolball_name = WoolballName { name };
            DocumentField {
                format_field: field,
                field: FieldType::WoolballName(woolball_name),
            }
        }

        FieldTypeName::EVMAddress => {
            let address_hex_str = Text::new(&field.fdescription).prompt().unwrap();
            DocumentField {
                format_field: field,
                field: FieldType::EVMAddress(address_hex_str),
            }
        }

        FieldTypeName::Hash => {
            let hash_hex_str: String = Text::new(&field.fdescription).prompt().unwrap();
            let hash = babyjubjub::hex_to_fq(&hash_hex_str).unwrap();
            DocumentField {
                format_field: field,
                field: FieldType::Hash(hash),
            }
        }

        // Identical to Text in the input stage, but when needs to be signed
        // when is used in a document
        FieldTypeName::SignedText => {
            let text: String = Text::new(&field.fdescription).prompt().unwrap();
            DocumentField {
                format_field: field,
                field: FieldType::SignedText(text),
            }
        }

        _ => panic!("Unsupported field type."),
    }
}

// A string representation of a PubKey
// This way it's easier to work with it in TOML
#[derive(Serialize, Deserialize, Debug)]
struct PubKeyString {
    x: String,
    y: String,
}

// A string representation of a Signature
// This way it's easier to work with it in TOML
#[derive(Serialize, Deserialize, Debug)]
struct SignatureString {
    s: String,
    rx: String,
    ry: String,
}

// A string representation of a Signature
// This way it's easier to work with it in TOML
#[derive(Serialize, Deserialize, Debug)]
struct SignatureMessageString {
    hash: String,
    s: String,
    rx: String,
    ry: String,
}
