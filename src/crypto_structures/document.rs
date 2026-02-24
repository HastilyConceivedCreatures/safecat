use crate::{
    commands, consts,
    crypto_structures::{
        babyjubjub, proof_input, signature,
        woolball::{self, WoolballName},
    },
    serialization,
};
pub use ark_bn254::Fr as Fq;
use chrono::NaiveDate;
use chrono::{DateTime, Utc};
use inquire::{formatter::DEFAULT_DATE_FORMATTER, CustomType, Text};
use reqwest;
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
    SignedEVMAddress(String),             // EVMAddress that requires a digital signature
    HashPath(proof_input::HashPath),
    Zed(babyjubjub::PubKey),
}

/// Enum for field type names, used to define the type of a field without holding values.
/// Make sure that this enum stays synchroniZed with FieldType to avoid mismatches.
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
    SignedEVMAddress,
    HashPath,
    Zed,
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
    pub fn to_fq_vector(&self) -> Vec<Fq> {
        self.document_fields
            .iter()
            .flat_map(|document_field| {
                let field = &document_field.field;

                match field {
                    // Convert a text field into an Fq element using `message_to_fq_vec`.
                    FieldType::Text(ref text) => {
                        let text_bn254 = babyjubjub::message_to_fq_vec(text).unwrap();
                        vec![text_bn254].into_iter()
                    }

                    // Convert an integer into an Fq element.
                    FieldType::Integer(ref number) => vec![Fq::from(*number)].into_iter(),

                    // Convert a timestamp into an Fq element.
                    FieldType::Timestamp(ref timestamp) => {
                        let timestamp_fq = babyjubjub::datetime_utc_to_fq(*timestamp).unwrap();
                        vec![timestamp_fq].into_iter()
                    }

                    // Convert an age (integer) into an Fq element.
                    FieldType::Age(ref age) => vec![Fq::from(*age)].into_iter(),

                    // Convert a Babyjubjub public key into multiple Fq elements.
                    FieldType::BabyjubjubPubkey(ref babyjubjub_pubkey) => {
                        babyjubjub_pubkey.to_fq_vec().into_iter()
                    }

                    // Convert a WoolballName into multiple Fq elements.
                    FieldType::WoolballName(ref woolball_name) => {
                        woolball_name.to_fq_vec().into_iter()
                    }

                    // Convert an EVM address into an Fq element.
                    FieldType::EVMAddress(ref evm_address) => {
                        let evm_address_bn254 = babyjubjub::evm_address_to_fq(evm_address).unwrap();
                        vec![evm_address_bn254].into_iter()
                    }

                    // Convert a signature into multiple Fq elements.
                    FieldType::Signature(ref signature) => signature.to_fq_vec().into_iter(),

                    // Push a hash field as a single Fq element.
                    FieldType::Hash(ref hash) => vec![*hash].into_iter(),

                    // Convert signed text into a hash and its signature.
                    FieldType::SignedText(ref text) => {
                        // Hash and sign text
                        let (signature, hash_fq) =
                            commands::sign::sign_message(text.clone()).unwrap();

                        // Push text's hash
                        let mut result = vec![hash_fq];

                        // Push signature
                        result.extend(signature.to_fq_vec());
                        result.into_iter()
                    }

                    // Convert a signed EVM address into its Fq representation and signature.
                    FieldType::SignedEVMAddress(ref address) => {
                        // Convert address to Fq
                        let address_fq = babyjubjub::evm_address_to_fq(address).unwrap();

                        // Sign the address
                        let address_fq_as_str = babyjubjub::fq_to_dec_str(&address_fq);
                        let (signature, _) =
                            commands::sign::sign_babyjubjub_fq(address_fq_as_str).unwrap();

                        // Push address
                        let mut result = vec![address_fq];

                        // Push signature
                        result.extend(signature.to_fq_vec());
                        result.into_iter()
                    }

                    // Convert a HashPath into Fq elements.
                    FieldType::HashPath(ref hash_path) => {
                        // Convert the index to Fq and push to the result.
                        let mut result = vec![Fq::from(hash_path.index)];

                        // Convert each element in the path (Vec<String>) to Fq and push to the result.
                        for path_element in &hash_path.path {
                            let path_element_fq =
                                babyjubjub::message_to_fq_vec(path_element).unwrap();
                            result.push(path_element_fq);
                        }

                        result.into_iter()
                    }

                    // Zed IDs are a public key, and handled like babyjubjub pubkeys: turned into multiple Fq elements.
                    FieldType::Zed(ref babyjubjub_pubkey) => {
                        babyjubjub_pubkey.to_fq_vec().into_iter()
                    }
                }
            })
            .collect()
    }

    /// Converts the document fields to a TOML table.
    /// TODO: add to format an option to mark if a value should be converted to Fq in the Toml
    pub fn to_toml_table(&self) -> Map<String, Value> {
        // Create an empty TOML table
        let mut toml_table = Map::new();

        // Convert fields to TOML key-value pairs
        for document_field in &self.document_fields {
            match &document_field.field {
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

                FieldType::EVMAddress(address) => {
                    toml_table.insert(
                        document_field.format_field.fname.clone(),
                        Value::String(address.clone()),
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

                    let signature_message = SignatureString {
                        s: signature.s.to_string(),
                        rx: signature.rx.to_string(),
                        ry: signature.ry.to_string(),
                    };

                    // Insert Hash
                    toml_table.insert(
                        document_field.format_field.fname.clone(),
                        Value::String(hash_fq.to_string()),
                    );

                    // Create a sub-table for the Signature
                    let mut sub_table = Map::new();
                    sub_table.insert("s".to_string(), Value::String(signature_message.s));
                    sub_table.insert("rx".to_string(), Value::String(signature_message.rx));
                    sub_table.insert("ry".to_string(), Value::String(signature_message.ry));

                    // Insert the signature
                    let key_with_suffix =
                        format!("{}_signature", document_field.format_field.fname);
                    toml_table.insert(key_with_suffix, Value::Table(sub_table));
                }

                FieldType::SignedEVMAddress(address) => {
                    // Insert address
                    toml_table.insert(
                        document_field.format_field.fname.clone(),
                        Value::String(address.clone()),
                    );

                    // Sign the address and insert signature
                    // First, convert the address into Fq
                    let address_fq = babyjubjub::evm_address_to_fq(address).unwrap();

                    // Then sign the Fq
                    let address_fq_as_str = babyjubjub::fq_to_dec_str(&address_fq);
                    let (signature, _) =
                        commands::sign::sign_babyjubjub_fq(address_fq_as_str).unwrap();

                    let signature_message = SignatureString {
                        s: signature.s.to_string(),
                        rx: signature.rx.to_string(),
                        ry: signature.ry.to_string(),
                    };

                    // Create a sub-table for the Signature
                    let mut sub_table = Map::new();
                    sub_table.insert("s".to_string(), Value::String(signature_message.s));
                    sub_table.insert("rx".to_string(), Value::String(signature_message.rx));
                    sub_table.insert("ry".to_string(), Value::String(signature_message.ry));

                    let key_with_suffix =
                        format!("{}_signature", document_field.format_field.fname);
                    toml_table.insert(key_with_suffix, Value::Table(sub_table));
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

                FieldType::Zed(pubkey) => {
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
            // Prompt user for input
            let pubkey_or_woolball_name = Text::new(&field.fdescription).prompt().unwrap();

            // Check if the input ends with `#`
            if pubkey_or_woolball_name.ends_with('#') {
                // Print commentary about fetching the public key
                println!(
                    "{}Reading the public key from Woolball for target name: {}{}",
                    consts::ORANGE_COLOR_ANSI,
                    pubkey_or_woolball_name,
                    consts::RESET_COLOR_ANSI
                );

                // Fetch the public key asynchronously
                let runtime = tokio::runtime::Runtime::new().unwrap();
                let babyjubjub_pubkey_result = runtime.block_on(
                    woolball::fetch_publickey_for_wbname(pubkey_or_woolball_name.clone()),
                );

                // Handle the result
                match babyjubjub_pubkey_result {
                    Ok(babyjubjub_pubkey) => DocumentField {
                        format_field: field,
                        field: FieldType::BabyjubjubPubkey(babyjubjub_pubkey),
                    },
                    Err(err) => {
                        eprintln!(
                            "{}Failed to fetch public key: {}{}",
                            consts::RED_COLOR_ANSI,
                            err,
                            consts::RESET_COLOR_ANSI
                        );
                        panic!("Error reading Woolball name.");
                    }
                }
            } else {
                // If no `#`, treat input as a hexadecimal public key
                let babyjubjub_pubkey: babyjubjub::PubKey =
                    babyjubjub::PubKey::from_str_hex(pubkey_or_woolball_name).unwrap();
                DocumentField {
                    format_field: field,
                    field: FieldType::BabyjubjubPubkey(babyjubjub_pubkey),
                }
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

        // Identical to Text in the input stage, but needs to be signed
        // when is used in a document
        FieldTypeName::SignedText => {
            let text: String = Text::new(&field.fdescription).prompt().unwrap();
            DocumentField {
                format_field: field,
                field: FieldType::SignedText(text),
            }
        }

        // Identical to EVMAddress in the input stage, but needs to be signed
        // when is used in a document
        FieldTypeName::SignedEVMAddress => {
            let address_hex_str = Text::new(&field.fdescription).prompt().unwrap();
            DocumentField {
                format_field: field,
                field: FieldType::SignedEVMAddress(address_hex_str),
            }
        }

        // Zed ID: exchange it via the server using a one-time code confirmation
        FieldTypeName::Zed => {
            const SERVER: &str = "http://zed-test.almonit.club";

            let bob_name = Text::new("Your name: ")
                .prompt()
                .expect("Failed to read name");

            let code_str = Text::new("One-time code (6 digits): ")
                .prompt()
                .expect("Failed to read code");

            let code: u32 = code_str.parse().expect("Code must be 6 digits");

            let client = reqwest::blocking::Client::new();

            // Submit code + name
            let res = client
                .post(format!("{}/submit-code", SERVER))
                .json(&serde_json::json!({
                    "code": code.to_string(),
                    "name": bob_name
                }))
                .send()
                .expect("Failed to submit to server");

            if !res.status().is_success() {
                panic!("Server error: {}", res.status());
            }

            println!("Code submitted. Waiting for approval...");

            // Poll until key is ready
            let pubkey_hex: String = loop {
                std::thread::sleep(std::time::Duration::from_secs(4));

                let res = client
                    .get(format!("{}/get-key", SERVER))
                    .query(&[("code", code.to_string())])
                    .send()
                    .expect("Failed to poll server");

                if res.status().is_success() {
                    let json: serde_json::Value = res.json().expect("Invalid JSON");

                    if let Some(key) = json["publicKey"].as_str() {
                        break key.to_string();
                    }
                }
                // loop continues on failure / no key yet
            };

            let babyjubjub_pubkey = babyjubjub::PubKey::from_str_hex(pubkey_hex)
                .expect("Invalid public key format from server");

            DocumentField {
                format_field: field,
                field: FieldType::BabyjubjubPubkey(babyjubjub_pubkey),
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
