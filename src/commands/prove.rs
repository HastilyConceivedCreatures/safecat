use crate::crypto_structures::{
    babyjubjub,
    certificate::Cert,
    signature::SignatureAndSigner,
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use toml;

pub fn prove() -> io::Result<()> {
    // Step 1: Get list of files from certs/received
    let certs_path = Path::new("certs/received");
    let files = fs::read_dir(certs_path)?;

    let mut found_cert_option: Option<Cert> = None;
    let mut found_signature_option: Option<SignatureAndSigner> = None;

    // Step 2: Read type of each file until it finds a file where type is "birth"
    for file in files {
        let entry = file?;
        let path = entry.path();
        if path.is_file() {
            let file = File::open(&path)?;
            let mut lines = io::BufReader::new(file).lines();
            if let Some(Ok(first_line)) = lines.next() {
                let cert: Cert = serde_json::from_str(&first_line).unwrap();
                if cert.cert_type == "babyjubjub" {
                    // Store the cert to be used outside the loop
                    found_cert_option = Some(cert);

                    // Deserialize the second line into Signature
                    if let Some(Ok(second_line)) = lines.next() {
                        let signature: SignatureAndSigner =
                            serde_json::from_str(&second_line).unwrap();
                        println!("Deserialized Signature: {:?}", signature);

                        // Store the signature to be used outside the loop
                        found_signature_option = Some(signature);
                    }

                    break;
                }
            }
        }
    }

    let found_cert = found_cert_option.unwrap();
    let found_signature = found_signature_option.unwrap();

    // Extract details from Cert
    let signer_id = found_signature.signer.to_hex_str();

    // Read the JSON data
    let trust_kernel_json =
        fs::read_to_string("data/trust_kernel.json").expect("Unable to read trust_kernel.json");
    let trust_kernel: TrustKernel =
        serde_json::from_str(&trust_kernel_json).expect("JSON was not well-formatted");

    // Find the specified member
    let member_opt = trust_kernel
        .members
        .iter()
        .find(|m| m.name.to_lowercase() == signer_id.to_lowercase());

    if let Some(member) = member_opt {
        // Fill in the member data
        let mut prover = Prover {
            trust_kernel_root: trust_kernel.root,
            last_checked_timestamp: Utc::now().timestamp().to_string(),
            expiration: found_cert.expiration.timestamp().to_string(),
            birthdate: found_cert.body[0]
                .field
                .as_timestamp()
                .unwrap()
                .timestamp()
                .to_string(),
            person: *found_cert.to[0].field.as_babyjubjub_pubkey().unwrap(),
            signatures: vec![found_signature],
            signers_hash_path: vec![SignersHashPath {
                index: member.index,
                path: member.path.clone(),
            }],
        };

        // Serialize to TOML and write to output file
        let prover_toml = prover.to_toml();
        let toml_string = toml::to_string_pretty(&prover_toml).expect("Failed to serialize TOML");
        fs::write("output/prover.toml", toml_string).expect("Unable to write prover.toml");

        println!("Successfully wrote prover.toml");
    } else {
        eprintln!("Member '{}' not found", signer_id);
    }

    Ok(())
}

#[derive(Serialize, Deserialize, Debug)]
struct TrustKernel {
    root: String,
    members: Vec<Member>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Member {
    name: String,
    x: String,
    y: String,
    index: u32,
    path: Vec<String>,
}

#[derive(Debug)]
struct Prover {
    trust_kernel_root: String,
    last_checked_timestamp: String,
    expiration: String,
    birthdate: String,
    person: babyjubjub::PubKey,
    signatures: Vec<SignatureAndSigner>,
    signers_hash_path: Vec<SignersHashPath>,
}

impl Prover {
    pub fn to_toml(&mut self) -> ProverToml {
        let person = Person {
            x: babyjubjub::fq_to_hex_str(&self.person.x),
            y: babyjubjub::fq_to_hex_str(&self.person.y),
        };

        let mut signatures: Vec<SignatureToml> = vec![];
        let mut signers: Vec<Person> = vec![];

        for signature_and_signer in self.signatures.iter_mut() {
            let signature_toml = SignatureToml {
                s: babyjubjub::fr_to_hex_string(&signature_and_signer.signature.s),
                rx: babyjubjub::fq_to_hex_str(&signature_and_signer.signature.rx),
                ry: babyjubjub::fq_to_hex_str(&signature_and_signer.signature.ry),
            };

            let signer_toml = Person {
                x: babyjubjub::fq_to_hex_str(&signature_and_signer.signer.x),
                y: babyjubjub::fq_to_hex_str(&signature_and_signer.signer.y),
            };

            signatures.push(signature_toml);
            signers.push(signer_toml);
        }

        ProverToml {
            trust_kernel_root: self.trust_kernel_root.clone(),
            last_checked_timestamp: self.last_checked_timestamp.clone(),
            expiration: self.expiration.clone(),
            birthdate: self.birthdate.clone(),
            person: person,
            signatures: signatures,
            signers: signers,
            signers_hash_path: self.signers_hash_path.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ProverToml {
    trust_kernel_root: String,
    last_checked_timestamp: String,
    expiration: String,
    birthdate: String,
    person: Person,
    signatures: Vec<SignatureToml>,
    signers: Vec<Person>,
    signers_hash_path: Vec<SignersHashPath>,
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
struct Signer {
    x: String,
    y: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SignersHashPath {
    index: u32,
    path: Vec<String>,
}
