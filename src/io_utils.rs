/* Collection of IO functions for
saving, loading, and printing */

use babyjubjub_ark::PrivateKey;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::error::Error as stdError;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::{fs, fs::File};

use crate::crypto_structures::{certificate::Cert, signature::Signature};
use crate::Error;

pub fn save_private_key(filename: &str, private_key: &PrivateKey) -> Result<(), Error> {
    print!("New private_key: ");

    // Create file
    let mut file = File::create(filename)?;

    // Extract key array from private key
    let key_array: [u8; 32] = private_key.key;

    // Write the key array in 02x format, meaning 2 chars per number
    for &num in &key_array {
        write!(file, "{:02x}", num)?;
        print!("{:02x?}", num);
    }

    // end the line of the private key
    write!(file, "\n")?;
    println!("");

    // ANSI escape codes for green color
    let green_color_code = "\x1b[32m";
    let reset_color_code = "\x1b[0m";

    // Notify after saving the private key into a file
    println!(
        "Saved the new private key in {}{}{} file",
        green_color_code, filename, reset_color_code
    );

    Ok(())
}

pub fn load_private_key(filename: &str) -> Result<PrivateKey, Error> {
    // Read the content of the file into a string
    let mut private_key_hex_string = String::new();
    File::open(filename)?.read_to_string(&mut private_key_hex_string)?;

    // Create a buffer to read the content into
    let mut numbers: [u8; 32] = [0; 32];

    // Parse the hex string into a numbers
    let key_array = hex::decode(private_key_hex_string.trim())?;
    numbers.copy_from_slice(&key_array);

    // let numbers_vec = numbers.to_vec();
    let numbers_vec: Vec<u8> = numbers.to_vec();
    let private_key: PrivateKey = PrivateKey::import(numbers_vec)?;

    Ok(private_key)
}

pub fn print_u8_array(arr: &[u8], format: &str) {
    for &element in arr {
        if format == "hex" {
            print!("{:02x?}", element);
        } else if format == "dec" {
            print!("{:?}", element);
        }
    }
}

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
pub fn save_certificate(cert: Cert, signature: Signature) -> Result<String, Error> {
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

// print certificates in a folder
pub fn show_certs(folder_path: &str) -> Result<(), std::io::Error> {
    // Check if the folder exists
    if !Path::new(folder_path).exists() {
        println!("Folder '{}' doesn't exist.", folder_path);
        return Ok(());
    }

    // Get list of files in the specified folder
    let file_paths = fs::read_dir(folder_path)?
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, std::io::Error>>()?;

    println!("{: <8} {: <14} {: <14} {}", "Index", "rx", "ry", "Type");
    println!("{}", "-".repeat(45));

    for (index, file_path) in file_paths.iter().enumerate() {
        let rx;
        let ry;
        let cert_type;

        // Open the file
        let file = File::open(&file_path)?;
        let mut reader = BufReader::new(file);

        // Read first line (JSON containing "type")
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let json_type: serde_json::Value = serde_json::from_str(&line)?;

        // Read second line (JSON containing "rx" and "ry")
        line.clear();
        reader.read_line(&mut line)?;
        let json_rx_ry: serde_json::Value = serde_json::from_str(&line)?;

        // Extract required fields
        if let (Some(type_val), Some(rx_val), Some(ry_val)) = (
            json_type.get("type"),
            json_rx_ry.get("rx"),
            json_rx_ry.get("ry"),
        ) {
            cert_type = type_val.as_u64().unwrap_or_default();
            rx = rx_val.as_str().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid rx value")
            })?;
            ry = ry_val.as_str().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid ry value")
            })?;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid JSON format",
            ));
        }

        // Print file info
        println!(
            "{: <8} {: <14} {: <14} {}",
            index + 1,
            &rx[0..12],
            &ry[0..12],
            cert_type
        );
    }

    Ok(())
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
