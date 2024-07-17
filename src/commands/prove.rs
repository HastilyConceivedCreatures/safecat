use crate::crypto_structures::{
    babyjubjub,
    certificate::{Cert, FieldType},
};
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

    let mut found_cert: Option<Cert> = None;
    let mut found_signature: Option<Signature> = None;

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
                    found_cert = Some(cert);

                    // Deserialize the second line into Signature
                    if let Some(Ok(second_line)) = lines.next() {
                        let signature: Signature = serde_json::from_str(&second_line).unwrap();
                        println!("Deserialized Signature: {:?}", signature);

                        // Store the signature to be used outside the loop
                        found_signature = Some(signature);
                    }

                    break;
                }
            }
        }
    }

    // Extract details from Cert
    let mut signer_id = "".to_string();
    match &found_cert.unwrap().to[0].field {
        FieldType::BabyjubjubPubkey(pubkey) => {
            signer_id = pubkey.to_str_hex();
        }
        _ => {
            // Handle other variants or do nothing
            println!("error");
        }
    }

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
        // Read the TOML template
        let mut prover: Prover = toml::from_str(
            &fs::read_to_string("data/prover-one-cert-path-2.toml")
                .expect("Unable to read prover-one-cert-path-2.toml"),
        )
        .expect("TOML was not well-formatted");

        // Fill in the member data
        prover.trust_kernel_root = trust_kernel.root.clone();
        prover.signers = vec![Signer {
            x: member.x.clone(),
            y: member.y.clone(),
        }];
        prover.signers_hash_path = vec![SignersHashPath {
            index: member.index.to_string(),
            path: member.path.clone(),
        }];

        // Serialize to TOML and write to output file
        let toml_string = toml::to_string_pretty(&prover).expect("Failed to serialize TOML");
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

#[derive(Serialize, Deserialize, Debug)]
struct Member {
    name: String,
    x: String,
    y: String,
    index: u32,
    path: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Prover {
    trust_kernel_root: String,
    last_checked_timestamp: String,
    expiration: String,
    birthdate: String,
    person: Person,
    signature: Vec<Signature>,
    signers: Vec<Signer>,
    signers_hash_path: Vec<SignersHashPath>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Person {
    x: String,
    y: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Signature {
    s: String,
    rx: String,
    ry: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Signer {
    x: String,
    y: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct SignersHashPath {
    index: String,
    path: Vec<String>,
}
