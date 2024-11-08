use crate::{
    cast,
    crypto_structures::babyjubjub::{self, Fq},
    crypto_structures::document::{self, Document, FormatField},
};
use poseidon_ark::Poseidon;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Represents the format of a certificate, including fields for both the recipient and the body.
#[derive(Debug, Serialize, Deserialize)]
pub struct CertFormat {
    /// A vector of fields for the recipient (e.g., an ID).
    pub to: Vec<FormatField>,
    /// A vector of fields for the certificate body.
    pub body: Vec<FormatField>,
}

/// Represents a certificate with fields for the recipient and the body.
#[derive(Debug, Serialize, Deserialize)]
pub struct Cert {
    /// The certificate type (e.g., ID, DAO_membership).
    pub cert_type: String,
    /// The recipient fields for the certificate.
    pub to: Document,
    /// The body fields for the certificate.
    pub body: Document,
}

impl Cert {
    /// Computes a Poseidon hash of the certificate fields.
    pub fn poseidon_hash(&self) -> Fq {
        let poseidon_ark = Poseidon::new();
        let hash_fq = poseidon_ark.hash(self.to_fq_vector()).unwrap();
        hash_fq
    }

    /// Converts the certificate into a vector of `Fq` elements, making it easier to use in SNARKs.
    fn to_fq_vector(&self) -> Vec<Fq> {
        let mut cert_vec: Vec<Fq> = vec![];

        cert_vec.push(babyjubjub::message_to_fq_vec(&self.cert_type).unwrap());

        let mut to_vec = self.to.to_fq_vector();
        let mut body_vec = self.body.to_fq_vector();

        cert_vec.append(&mut to_vec);
        cert_vec.append(&mut body_vec);

        cert_vec
    }

    /// TODO: Refactor this method. The certificate name should be derived from its fields and types.
    ///       Consider moving this logic to the `Document` structure.
    pub fn name(&self) -> String {
        // Concatenate data from the `cert_type` and document fields.
        let mut data = String::new();

        // Add certificate type.
        data.push_str(&self.cert_type);

        // Add names of "to" fields.
        for field in &self.to.document_fields {
            data.push_str(&format!("{:?}{:?}", field.format_field.fname, field.field));
        }

        // Add names of "body" fields.
        for field in &self.body.document_fields {
            data.push_str(&format!("{:?}{:?}", field.format_field.fname, field.field));
        }

        // Hash the concatenated data.
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        let hash = hasher.finalize();

        // Convert the hash result to a BigInt, then to a string.
        let hashed_message_bigint = cast::hash_to_bigint(&hash[..]);
        let hashed_message_string = hashed_message_bigint.to_str_radix(10);

        hashed_message_string
    }
}

/// Inserts certificate data into a `Cert` instance, processing the fields based on the provided `CertFormat`.
pub fn insert_cert_data(format: CertFormat, cert_type: &str) -> Cert {
    let mut cert = Cert {
        cert_type: cert_type.to_string(),
        to: Document {
            document_fields: vec![],
        },
        body: Document {
            document_fields: vec![],
        },
    };

    // Process recipient fields.
    for field in format.to {
        let cert_field = document::process_document_field(field);
        cert.to.document_fields.push(cert_field);
    }

    // Process body fields.
    for field in format.body {
        let cert_field = document::process_document_field(field);
        cert.body.document_fields.push(cert_field);
    }

    cert
}
