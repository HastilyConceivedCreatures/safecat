use super::document::Format;
use crate::commands::prove::Member;
use crate::crypto_structures::{
    certificate::Cert,
    document::{self, Document, DocumentField, FieldType, FieldTypeName, FormatField},
    signature::SignatureAndSigner,
};
use crate::{consts, Error};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Read;

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
    signer_society_details: Member,
) -> Document {
    let mut proof_input_parameters: Vec<DocumentField> = Vec::new();

    // Create a DocumentField for certificate file
    let cert_type_field = DocumentField {
        format_field: FormatField {
            fname: "cert_type".to_string(),
            fdescription: "The type of the certificate".to_string(),
            ftype: FieldTypeName::Text,
        },
        field: FieldType::Text(cert.cert_type.clone()),
    };

    // Add the certificate to the input
    proof_input_parameters.push(cert_type_field);
    proof_input_parameters.append(&mut cert.to.document_fields);
    proof_input_parameters.append(&mut cert.body.document_fields);

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

    // Add additional fields from proof.toml

    // First calculate the certificate formats path
    let formats_folder_path = consts::DATA_DIR.to_string() + "/" + consts::CERTIFICATE_FORMATS;

    // Then construct the file path based on the `format` parameter
    let file_path = format!(
        "{}/{}/proofs/{}/proof.toml",
        formats_folder_path, cert_format, proof_format
    );

    // Now read the certificate format from the TOML file
    let input_format =
        read_document_format_from_toml(&file_path).expect("Couldn't read proof.toml file");

    let mut input_fields: Vec<DocumentField> = Vec::new();
    for field in input_format.fields {
        let input_field = document::process_document_field(field);
        input_fields.push(input_field);
    }

    proof_input_parameters.append(&mut input_fields);

    Document {
        document_fields: proof_input_parameters,
    }
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
