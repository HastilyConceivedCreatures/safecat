/* Collection of IO functions for
saving, loading, and printing */

use rand::seq::SliceRandom;
use rand::thread_rng;
use std::error::Error as stdError;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::{fs, fs::File};

use crate::crypto_structures::{certificate::Cert, signature::SignatureAndSigner};
use crate::Error;

// splits a 128 hex string into two 64 strings
pub fn split_hex_string(input: &str) -> (String, String) {
    // Check if the input string has a length of 128 characters
    if input.len() != 128 {
        println!("public key is too short: must be a 128 characters hex");
        std::process::exit(1);
    }

    // Check if the input string contains only valid hex characters
    if !input.chars().all(|c| c.is_digit(16)) {
        println!("public key is not a hex number");
        std::process::exit(1);
    }

    // Split the string into two halves of length 64
    let (first_half, second_half) = input.split_at(64);

    (first_half.to_string(), second_half.to_string())
}

// saves a certificate
pub fn save_certificate(cert: Cert, signature: SignatureAndSigner) -> Result<String, Error> {
    // certificates folder
    let path = "certs/created";

    // Check if the folder exists
    let path_exists = fs::metadata(path).is_ok();

    if !path_exists {
        // If the folder doesn't exist, create it
        fs::create_dir_all(path).map_err(|e| format!("Can't create folder: {}", e))?;
        println!("Folder '{}' created successfully.", path);
    }

    // if filename exists, add  suffix to it such as "filename-1"
    let mut filename_index = 1;
    let mut filename = cert.name().to_string();

    while file_exists(path, &filename)? {
        filename = format!("{}-{}", filename, filename_index);
        filename_index += 1;
    }

    let filename_with_path = format!("certs/created/{}", filename);

    // Open the file in write mode, creating it if it doesn't exist
    let mut file = File::create(filename_with_path.clone())
        .map_err(|e| format!("Unable to write file: {}", e))?;

    // create jsons
    let cert_json = serde_json::to_string(&cert)?;
    let signature_json = serde_json::to_string(&signature)?;

    // Write the first string followed by a newline character
    [
        cert_json.as_bytes(),
        b"\n",
        signature_json.as_bytes(),
        b"\n",
    ]
    .into_iter()
    .map(|bytes| {
        file.write_all(bytes)
            .map_err(|e| format!("Unable to write file: {}", e).into())
    })
    .collect::<Result<Vec<()>, Error>>()?;

    Ok(filename_with_path)
}

// checks if "filename" exists in "folder"
pub fn file_exists(folder: &str, filename: &str) -> Result<bool, Error> {
    let current_dir = std::env::current_dir()?;
    let file_path = current_dir.join(folder).join(filename);
    Ok(file_path.exists())
}

pub fn read_random_line<P>(filename: P) -> Result<String, Box<dyn stdError>>
where
    P: AsRef<Path>,
{
    // Open the file
    let file = File::open(filename)?;
    let reader = BufReader::new(file);

    // Collect lines into a vector
    let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;

    // Get a random line
    let mut rng = thread_rng();
    match lines.choose(&mut rng) {
        Some(line) => Ok(line.clone()),
        None => Err("The file is empty".into()),
    }
}
