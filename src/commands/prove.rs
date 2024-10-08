use crate::crypto_structures::{
    babyjubjub::PubKey, certificate::Cert, proof_input, signature::SignatureAndSigner,
};
use crate::{consts, Error};

use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::process::Command;
use toml;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

pub fn prove(cert_format: &String, proof_format: &String, no_execute: bool) -> io::Result<()> {
    // Stating what we prove
    println!(
        "proving claim {} {} {} for format {} {}. {}",
        consts::RED_COLOR_ANSI,
        proof_format,
        consts::RESET_COLOR_ANSI,
        consts::RED_COLOR_ANSI,
        cert_format,
        consts::RESET_COLOR_ANSI,
    );

    // Find relevant certificate
    let (found_cert, found_signature) = find_cert_and_signature("certs/received", cert_format)
        .expect("Did not find any fitting certificates.");

    // Find the hash path of the signers of the certificate
    let member = find_hash_path(found_signature.signer);

    // Create a document with proof input
    let proof_input_document = proof_input::create_proof_input(
        (*cert_format).clone(),
        proof_format.clone(),
        found_cert,
        found_signature,
        member,
    );

    // Serialize to TOML and write to output file
    let prover_toml = proof_input_document.to_toml_table();
    let toml_string = toml::to_string_pretty(&prover_toml).expect("Failed to serialize TOML");
    fs::write("data/Prover.toml", toml_string).expect("Unable to write prover.toml");

    println!("Successfully wrote data/Prover.toml");

    if no_execute {
        println!("NOT EXECUTING INDEED!");
    } else {
        println!("EXECUTING!");
    }

    // prove_with_nargo_bb();
    // } else {
    //     eprintln!("Member '{}' not found", signer_id);
    // }

    Ok(())
}

#[derive(Serialize, Deserialize, Debug)]
struct TrustKernel {
    root: String,
    members: Vec<Member>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Member {
    name: String,
    x: String,
    y: String,
    pub index: u32,
    pub path: Vec<String>,
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

fn find_cert_and_signature(
    files_path: &str,
    cert_format: &str,
) -> Result<(Cert, SignatureAndSigner), Error> {
    // Get the list of files from certs/received folder
    let certs_path = Path::new(files_path);
    let files = fs::read_dir(certs_path)?;

    // These variables will hold the certificates and signatures we find
    let mut found_cert_option: Option<Cert> = None;
    let mut found_signature_option: Option<SignatureAndSigner> = None;

    // Step 2: Read type of each file until it finds a file where type equals "cert_format"
    for file in files {
        let entry = file?;
        let path = entry.path();
        if path.is_file() {
            let file = File::open(&path)?;
            let mut lines = io::BufReader::new(file).lines();
            if let Some(Ok(first_line)) = lines.next() {
                let cert: Cert = serde_json::from_str(&first_line).unwrap();
                if cert.cert_type == *cert_format {
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

    // Return the found Cert and Signature, or an error if not found
    if let (Some(cert), Some(signature_and_signer)) = (found_cert_option, found_signature_option) {
        Ok((cert, signature_and_signer))
    } else {
        Err(Box::from(
            "Did not find any fitting certificates or signatures",
        ))
    }
}

fn find_hash_path(signer: PubKey) -> Member {
    // Extract details from Cert
    let signer_id = signer.to_hex_str();

    // Read the JSON data
    let trust_kernel_json = fs::read_to_string("data/societies/woolball.json")
        .expect("Unable to read trust_kernel.json");
    let trust_kernel: TrustKernel =
        serde_json::from_str(&trust_kernel_json).expect("JSON was not well-formatted");

    // Find the specified member
    let member_opt = trust_kernel
        .members
        .iter()
        .find(|m| m.name.to_lowercase() == signer_id.to_lowercase());

    member_opt.expect("Didn't find member").clone()
}

// fn prove_with_nargo_bb() {
//     // Change the current working directory to 'data/NoirTargetedProofs'
//     let data_noir_dir = "data/NoirTargetedProofs";

//     // Execute the first command
//     let nargo_output = Command::new("nargo")
//         .arg("execute")
//         .arg("witness-human")
//         .current_dir(data_noir_dir)
//         .output()
//         .expect("Failed to execute nargo command");

//     // Check if the nargo command was successful
//     if !nargo_output.status.success() {
//         eprintln!("nargo command failed with output: {:?}", nargo_output);
//         std::process::exit(1);
//     }

//     // Execute the second command
//     let bb_output = Command::new("bb")
//         .arg("prove")
//         .arg("-b")
//         .arg("./target/verify_certificates.json")
//         .arg("-w")
//         .arg("./target/witness-human.gz")
//         .arg("-o")
//         .arg("./target/proof")
//         .current_dir(data_noir_dir)
//         .output()
//         .expect("Failed to execute bb command");

//     // Check if the bb command was successful
//     if bb_output.status.success() && bb_output.stdout.is_empty() {
//         println!("Proof succeed! The proof is in file target/proof");
//     } else {
//         eprintln!("bb command failed with output: {:?}", bb_output);
//         std::process::exit(1);
//     }

//     // Path to the target directory
//     let target_dir = Path::new(data_noir_dir).join("target");

//     // Create a zip file containing 'hello_world.json' and 'proof'
//     let zip_file_path = target_dir.join("output.zip");
//     let zip_file = File::create(&zip_file_path).expect("Failed to create zip file");
//     let mut zip_writer = ZipWriter::new(zip_file);

//     // Specify the compression method (e.g., Stored or Deflated)
//     let options = SimpleFileOptions::default()
//         .compression_method(zip::CompressionMethod::Stored)
//         .unix_permissions(0o755);

//     // Files to include in the zip
//     let files_to_zip = vec!["verify_certificates.json", "proof"];

//     for file_name in &files_to_zip {
//         let file_path = target_dir.join(file_name);
//         let mut file = File::open(&file_path).expect("Failed to open file");

//         zip_writer
//             .start_file(file_name, options)
//             .expect("Failed to add file to zip");

//         io::copy(&mut file, &mut zip_writer).expect("Failed to write file to zip");
//     }

//     zip_writer.finish().expect("Failed to finalize zip file");
// }
