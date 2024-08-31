use crate::crypto_structures::{
    babyjubjub,
    certificate::Cert,
    signature::SignatureAndSigner,
};

use crate::commands::sign;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use toml;
use std::process::Command;
use zip::{ZipWriter, write::SimpleFileOptions};

pub fn prove(what: &String, to_whom: &String) -> io::Result<()> {
    // Stating what we prove
    println!("proving: {}. Lol what? we only prove one thing for now rofl", what);

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

                        // Store the signature to be used outside the loop
                        found_signature_option = Some(signature);
                    }

                    break;
                }
            }
        }
    }

    let found_cert = found_cert_option.expect("Did not find any fitting certificates.");
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
            cert_type: found_cert.cert_type,
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
            to_whom: to_whom.to_string(),
        };

        // Serialize to TOML and write to output file
        let prover_toml = prover.to_toml();
        let toml_string = toml::to_string_pretty(&prover_toml).expect("Failed to serialize TOML");
        fs::write("data/NoirTargetedProofs/Prover.toml", toml_string).expect("Unable to write prover.toml");

        println!("Successfully wrote data/NoirTargetedProofs/Prover.toml");

        prove_with_nargo_bb();
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
    cert_type: String,
    trust_kernel_root: String,
    last_checked_timestamp: String,
    expiration: String,
    birthdate: String,
    person: babyjubjub::PubKey,
    signatures: Vec<SignatureAndSigner>,
    signers_hash_path: Vec<SignersHashPath>,
    to_whom: String,
}

impl Prover {
    pub fn to_toml(&mut self) -> ProverToml {
        let cert_type = babyjubjub::message_to_fq_vec(&self.cert_type).unwrap();
        let cert_type_str_dec = babyjubjub::fq_to_dec_str(&cert_type);

        let person = Person {
            x: babyjubjub::fq_to_dec_str(&self.person.x),
            y: babyjubjub::fq_to_dec_str(&self.person.y),
        };

        let mut signatures: Vec<SignatureToml> = vec![];
        let mut signers: Vec<Person> = vec![];

        for signature_and_signer in self.signatures.iter_mut() {
            let signature_toml = SignatureToml {
                s: babyjubjub::fr_to_dec_string(&signature_and_signer.signature.s),
                rx: babyjubjub::fq_to_dec_str(&signature_and_signer.signature.rx),
                ry: babyjubjub::fq_to_dec_str(&signature_and_signer.signature.ry),
            };

            let signer_toml = Person {
                x: babyjubjub::fq_to_dec_str(&signature_and_signer.signer.x),
                y: babyjubjub::fq_to_dec_str(&signature_and_signer.signer.y),
            };

            signatures.push(signature_toml);
            signers.push(signer_toml);
        }

        let (to_whom_signature, to_whom_fq) = sign::sign_message(self.to_whom.clone()).unwrap();
        let to_whom_str_dec = babyjubjub::fq_to_dec_str(&to_whom_fq);
        let to_whom_signature_toml = SignatureToml {
            s: babyjubjub::fr_to_dec_string(&to_whom_signature.s),
            rx: babyjubjub::fq_to_dec_str(&to_whom_signature.rx),
            ry: babyjubjub::fq_to_dec_str(&to_whom_signature.ry),
        };


        ProverToml {
            cert_type: cert_type_str_dec,
            trust_kernel_root: self.trust_kernel_root.clone(),
            last_checked_timestamp: self.last_checked_timestamp.clone(),
            expiration: self.expiration.clone(),
            birthdate: self.birthdate.clone(),
            person: person,
            signatures: signatures,
            signers: signers,
            signers_hash_path: self.signers_hash_path.clone(),
            to_whom: to_whom_str_dec,
            to_whom_signature: to_whom_signature_toml,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ProverToml {
    cert_type: String,
    trust_kernel_root: String,
    last_checked_timestamp: String,
    expiration: String,
    birthdate: String,
    person: Person,
    signatures: Vec<SignatureToml>,
    signers: Vec<Person>,
    signers_hash_path: Vec<SignersHashPath>,
    to_whom: String,
    to_whom_signature: SignatureToml,
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

fn prove_with_nargo_bb() {
    // Change the current working directory to 'data/NoirTargetedProofs'
    let data_noir_dir = "data/NoirTargetedProofs";

    // Execute the first command
    let nargo_output = Command::new("nargo")
        .arg("execute")
        .arg("witness-human")
        .current_dir(data_noir_dir)
        .output()
        .expect("Failed to execute nargo command");

    // Check if the nargo command was successful
    if !nargo_output.status.success() {
        eprintln!("nargo command failed with output: {:?}", nargo_output);
        std::process::exit(1);
    }

    // Execute the second command
    let bb_output = Command::new("bb")
        .arg("prove")
        .arg("-b")
        .arg("./target/verify_certificates.json")
        .arg("-w")
        .arg("./target/witness-human.gz")
        .arg("-o")
        .arg("./target/proof")
        .current_dir(data_noir_dir)
        .output()
        .expect("Failed to execute bb command");

    // Check if the bb command was successful
    if bb_output.status.success() && bb_output.stdout.is_empty() {
        println!("Proof succeed! The proof is in file target/proof");
    } else {
        eprintln!("bb command failed with output: {:?}", bb_output);
        std::process::exit(1);
    }

    // Path to the target directory
    let target_dir = Path::new(data_noir_dir).join("target");

    // Create a zip file containing 'hello_world.json' and 'proof'
    let zip_file_path = target_dir.join("output.zip");
    let zip_file = File::create(&zip_file_path).expect("Failed to create zip file");
    let mut zip_writer = ZipWriter::new(zip_file);

    // Specify the compression method (e.g., Stored or Deflated)
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o755);

    // Files to include in the zip
    let files_to_zip = vec!["verify_certificates.json", "proof"];

    for file_name in &files_to_zip {
        let file_path = target_dir.join(file_name);
        let mut file = File::open(&file_path).expect("Failed to open file");
        
        zip_writer.start_file(file_name, options).expect("Failed to add file to zip");

        io::copy(&mut file, &mut zip_writer).expect("Failed to write file to zip");
    }

    zip_writer.finish().expect("Failed to finalize zip file");
}
