/* Collection of IO functions for
saving, loading, and printing */

use rand::seq::SliceRandom;
use rand::thread_rng;
use std::error::Error as stdError;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::{fs, fs::File};

use crate::crypto_structures::{certificate::Cert, signature::SignatureAndSigner};
use crate::{consts, Error};

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
    let base_filename = cert.name();
    let mut filename = base_filename.clone();

    while file_exists(path, &filename)? {
        filename = format!("{}-{}", base_filename, filename_index);
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

// Helper function to delete directory if it exists, then create it
pub fn recreate_folder(folder_path: &Path) -> io::Result<()> {
    if folder_path.exists() {
        fs::remove_dir_all(folder_path)?;
    }
    fs::create_dir_all(folder_path)?;
    Ok(())
}

pub fn copy_temp_to_output() -> Result<(), io::Error> {
    let temp_path = Path::new(consts::TEMP_FOLDER);
    let output_path = Path::new(consts::OUTPUT_FOLDER);

    // Create the output directory if it doesn't exist
    if !output_path.exists() {
        fs::create_dir_all(output_path)?;
    }

    // Recursively copy the contents of the temp directory
    copy_dir_all(temp_path, output_path)?;

    Ok(())
}

// Helper function to recursively copy a directory
pub fn copy_dir_all(src: &Path, dst: &Path) -> Result<(), io::Error> {
    // Create the destination directory if it doesn't exist
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }

    // Iterate over the contents of the source directory
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            // If it's a directory, recursively copy it
            copy_dir_all(&src_path, &dst_path)?;
        } else if src_path.is_file() {
            // If it's a file, copy it to the destination directory
            fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

pub fn erase_temp_contents() -> Result<(), io::Error> {
    let temp_path = Path::new(consts::TEMP_FOLDER);

    // Check if the temp directory exists
    if temp_path.exists() {
        // Iterate through the contents of the temp directory
        for entry in fs::read_dir(temp_path)? {
            let entry = entry?;
            let path = entry.path();

            // Remove the file or directory
            if path.is_dir() {
                fs::remove_dir_all(&path)?;
            } else {
                fs::remove_file(&path)?;
            }
        }
    }

    Ok(())
}
