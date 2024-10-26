use super::babyjubjub;
use super::document::Format;
use crate::commands::prove::Member;
use crate::crypto_structures::{
    babyjubjub::PubKey,
    certificate::Cert,
    document::{self, Document, DocumentField, FieldType, FieldTypeName, FormatField},
    signature::SignatureAndSigner,
};
use crate::{consts, Error};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Read; // import to use from_str in structs

/// Represents additional parameters needed to create a proof, extending `FieldType`.
#[derive(Debug, Serialize, Deserialize)]
pub enum ProofParameters {
    Field(document::FieldType), // Reuses all the variants of the FieldType enum
    SignedMessage(String),      // Additional variant specific to ProofParameters
}

#[derive(Serialize, Deserialize, Debug)]
struct Person {
    x: String,
    y: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct SignatureToml {
    s: String,
    rx: String,
    ry: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProofInput {
    #[serde(default)]
    public: Vec<FormatField>,

    #[serde(default)]
    private: Vec<FormatField>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HashPath {
    pub index: u32,
    pub path: Vec<String>,
}

// Reads proof.toml from the proof_format of the cert_format.
// Fill up accordingly using existing data and inquire crate
// returns a vecotr of DocumentField to be added to the rest of the proof data
pub fn create_proof_input(
    cert_format: String,
    proof_format: String,
    mut cert: Cert,
    signature_and_signer: SignatureAndSigner,
) -> Result<Document, Error> {
    // Prepare an empty vector of DocumentField to fill with the proof data
    let mut proof_input_parameters: Vec<DocumentField> = Vec::new();

    let cert_hash = babyjubjub::message_to_fq_vec(&cert.cert_type)?;
    // Create a DocumentField for certificate type
    let cert_type_field = DocumentField {
        format_field: FormatField {
            fname: "cert_type".to_string(),
            fdescription: "The type of the certificate".to_string(),
            ftype: FieldTypeName::Text,
        },
        field: FieldType::Hash(cert_hash),
    };

    // Add the certificate to the input
    proof_input_parameters.push(cert_type_field);
    proof_input_parameters.append(&mut cert.to.document_fields);
    proof_input_parameters.append(&mut cert.body.document_fields);

    // Get additional proof parameters from user
    let (society, mut proof_input_from_format) = read_proof_input(cert_format, proof_format)?;

    // Add the input from format to the vector
    proof_input_parameters.append(&mut proof_input_from_format);

    // Add signer
    let signer_cert_field = DocumentField {
        format_field: FormatField {
            fname: "signer".to_string(),
            fdescription: "Singer of the certificate".to_string(),
            ftype: FieldTypeName::BabyjubjubPubkey,
        },
        field: FieldType::BabyjubjubPubkey(signature_and_signer.signer),
    };
    proof_input_parameters.push(signer_cert_field);

    // Find the hash path of the signers of the certificate
    let (signer_society_details, soceity_root) =
        find_hash_path(signature_and_signer.signer, &society)?;

    // Add society root
    let society_root_field = DocumentField {
        format_field: FormatField {
            fname: "society_root".to_string(),
            fdescription: "The root of the society the proof is made for".to_string(),
            ftype: FieldTypeName::Text,
        },
        field: FieldType::Text(soceity_root),
    };
    proof_input_parameters.push(society_root_field);

    // Add signature
    let signature_cert_field = DocumentField {
        format_field: FormatField {
            fname: "signature".to_string(),
            fdescription: "The certificate signature".to_string(),
            ftype: FieldTypeName::Signature,
        },
        field: FieldType::Signature(signature_and_signer.signature),
    };
    proof_input_parameters.push(signature_cert_field);

    // Add hashpath for signer
    let signer_hash_path = HashPath {
        index: signer_society_details.index,
        path: signer_society_details.path,
    };

    let hash_path_cert_field = DocumentField {
        format_field: FormatField {
            fname: "hash_path".to_string(),
            fdescription: "The hash path of the signer".to_string(),
            ftype: FieldTypeName::HashPath,
        },
        field: FieldType::HashPath(signer_hash_path),
    };
    proof_input_parameters.push(hash_path_cert_field);

    Ok(Document {
        document_fields: proof_input_parameters,
    })
}

// read_proof_format_from_file: read first certificate and add each field to the format, and then read the
// proof toml and add more fields -> this is the proof format!

// fill up the format from the certificate data
/// Represents a certificate with recipient fields, and body fields
#[derive(Debug, Serialize, Deserialize)]
pub struct DocumentFieldsDocument {
    /// A vector of proof inputs fields
    pub fields: Vec<DocumentField>,
}

pub fn read_document_format_from_toml(file_name: &str) -> Result<document::Format, Error> {
    let mut file = OpenOptions::new().read(true).open(file_name)?;

    let mut toml_string = String::new();
    file.read_to_string(&mut toml_string)?;

    let document_format: Format = toml::from_str(&toml_string)?;
    Ok(document_format)
}

// Return a tuple of the Member in the society and of a string of the society hash
fn find_hash_path(signer: PubKey, society: &str) -> Result<(Member, String), Error> {
    // Construct societies file path
    let societies_file_path =
        consts::DATA_DIR.to_string() + "/" + consts::SOCIENTY_FOLDER + "/" + society + ".json";

    // Extract details from Cert
    let signer_id = signer.to_hex_str();

    // Read the JSON data, propagating error if the file cannot be read
    let trust_kernel_json = fs::read_to_string(&societies_file_path)
        .map_err(|_| format!("Unable to read soceity file: {}", societies_file_path))?;

    // Deserialize the JSON data into the TrustKernel struct, handling potential errors
    let trust_kernel: TrustKernel =
        serde_json::from_str(&trust_kernel_json).map_err(|_| "JSON was not well-formatted")?;

    // Find the specified member by comparing lowercase names
    let member = trust_kernel
        .members
        .iter()
        .find(|m| m.name.to_lowercase() == signer_id.to_lowercase())
        .ok_or_else(|| format!("Didn't find member with ID: {}", signer_id))?;

    // Extract society root from the trust kernel
    let society_root: String = trust_kernel.root;

    // Return the member (cloned) and the society root
    Ok((member.clone(), society_root))
}

fn read_proof_input(
    cert_format: String,
    proof_format: String,
) -> Result<(String, Vec<DocumentField>), Error> {
    // Vector to hold processed proof input fields
    let mut proof_input_from_format: Vec<DocumentField> = Vec::new();

    // Default value for society in case it's not found in the input fields
    let mut society: String = consts::DEAFULT_SOCIETY.to_string();

    // First, calculate the certificate formats path
    let formats_folder_path = format!("{}/{}", consts::DATA_DIR, consts::CERTIFICATE_FORMATS);

    // Construct the file path based on the cert_format and proof_format parameters
    let file_path = format!(
        "{}/{}/proofs/{}/proof.toml",
        formats_folder_path, cert_format, proof_format
    );

    // Read the certificate format from the TOML file
    let input_format =
        read_document_format_from_toml(&file_path).expect("Couldn't read proof.toml file");

    // Process each field from the input format
    for field in input_format.fields {
        let input_field = document::process_document_field(field);

        // Check if the current field's type is `Text` and the name is "society"
        if input_field.format_field.fname == "society" {
            if let FieldType::Text(society_value) = &input_field.field {
                // Check if the society field is not empty
                if !society_value.is_empty() {
                    // Update the society variable with the value from the field
                    society = society_value.clone();
                }
            }
        } else {
            // Add the processed field to the vector
            proof_input_from_format.push(input_field);
        }
    }

    // Return the society value along with the processed fields
    Ok((society, proof_input_from_format))
}

#[derive(Serialize, Deserialize, Debug)]
struct TrustKernel {
    root: String,
    members: Vec<Member>,
}
