use crate::crypto_structures::{certificate::Cert, proof_input, signature::SignatureAndSigner};
use crate::{consts, io_utils, Error};

use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::process::Command;
use toml;

pub fn prove(cert_format: &String, proof_format: &String, no_execute: bool) -> Result<(), Error> {
    // Stating what we prove
    println!(
        "proving claim {} {} {} for format {} {}. {}",
        consts::SOFT_BLUE_COLOR_ANSI,
        proof_format,
        consts::RESET_COLOR_ANSI,
        consts::SOFT_BLUE_COLOR_ANSI,
        cert_format,
        consts::RESET_COLOR_ANSI,
    );

    // Find relevant certificate
    let (found_cert, found_signature) = find_cert_and_signature("certs/received", cert_format)?;

    // Create a document with proof input
    let proof_input_document = proof_input::create_proof_input(
        (*cert_format).clone(),
        proof_format.clone(),
        found_cert,
        found_signature,
    )?;

    // Serialize to TOML and write to output file
    let prover_toml = proof_input_document.to_toml_table();
    let toml_string =
        toml::to_string_pretty(&prover_toml).map_err(|_| "Failed to serialize TOML")?;
    fs::write("data/Prover.toml", toml_string).map_err(|_| "Unable to write prover.toml")?;

    println!("Successfully wrote data/Prover.toml");

    prepare_noir_project(cert_format, proof_format)?;

    if no_execute {
        io_utils::copy_temp_to_output()?;
    } else {
        prove_with_nargo_bb()?;
    }

    io_utils::erase_temp_contents()?;

    Ok(())
}

fn find_cert_and_signature(
    files_path: &str,
    cert_format: &str,
) -> Result<(Cert, SignatureAndSigner), Error> {
    // Get the list of files from certs/received folder
    let certs_path = Path::new(files_path);
    let files = fs::read_dir(certs_path)
        .map_err(|_| format!("folder '{}' doesn't exist", certs_path.display()))?;

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

fn prove_with_nargo_bb() -> Result<(), Error> {
    // Change the current working directory to 'data/NoirTargetedProofs'
    let data_noir_dir = consts::TEMP_FOLDER;

    // Execute the first command
    let nargo_output = Command::new("nargo")
        .arg("execute")
        .arg("witness-human")
        .current_dir(data_noir_dir)
        .output()
        .map_err(|_| "Failed to execute nargo command")?;

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
        .map_err(|_| "Failed to execute bb command")?;

    // Check if the bb command was successful
    if bb_output.status.success() && bb_output.stdout.is_empty() {
        println!("Proof succeed! The proof is in file target/proof");
    } else {
        eprintln!("bb command failed with output: {:?}", bb_output);
        std::process::exit(1);
    }

    // Path to the target directory
    // Path to the target directory
    let target_dir = Path::new(data_noir_dir).join("target");
    let proof_src = target_dir.join("proof");
    let proof_dest = Path::new(&consts::DATA_DIR).join("proof");

    // Copy the proof file to the DATA_DIR
    fs::copy(&proof_src, &proof_dest).map_err(|e| format!("Failed to copy proof file: {}", e))?;

    Ok(())
}

// Main function as requested
fn prepare_noir_project(cert_format: &str, proof_format: &str) -> io::Result<()> {
    let temp_folder = Path::new(consts::TEMP_FOLDER);

    let noir_template_folder_path =
        consts::DATA_DIR.to_string() + "/" + consts::NOIR_TEMPLATE_FOLDER;
    let noir_template_folder = Path::new(&noir_template_folder_path);

    // Step 1: Delete everything in 'temp' folder, recreate it
    io_utils::recreate_folder(temp_folder)?;

    // Step 2: Copy everything from 'noir_project_template' to 'temp'
    io_utils::copy_dir_all(noir_template_folder, temp_folder)?;

    // Step 3: Copy main.nr file from data/formats/<cert_format>/proofs/<proof_format>/main.nr
    let main_nr_src = PathBuf::from(format!(
        "data/formats/{}/proofs/{}/main.nr",
        cert_format, proof_format
    ));
    let main_nr_dst = temp_folder.join("src/main.nr");

    // Create src folder in temp if it doesn't exist
    if let Some(parent) = main_nr_dst.parent() {
        fs::create_dir_all(parent)?;
    }

    // Copy the file, overwrite if needed
    fs::copy(main_nr_src, main_nr_dst)?;

    // Step 4: Copy Prover.toml from data/Prover.toml to temp folder
    let prover_toml_src_path = consts::DATA_DIR.to_string() + "/Prover.toml";
    let prover_toml_src = Path::new(&prover_toml_src_path);
    let prover_toml_dst = temp_folder.join("Prover.toml");

    // Copy the Prover.toml file to the temp directory, overwrite if needed
    fs::copy(prover_toml_src, prover_toml_dst)?;

    Ok(())
}

// These structs are used to give the Toml file a nice structure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Member {
    pub name: String,
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
