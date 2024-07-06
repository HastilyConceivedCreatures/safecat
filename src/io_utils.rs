/* Collection of IO functions for
saving, loading, and printing */

use babyjubjub_ark::{PrivateKey, Signature};
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::error::Error as stdError;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::{fs, fs::File};

use crate::cast; // module for casting between types
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

// // Verifies a timestamp relative to the current time, checking if it is within specified
// // time bounds. Takes a timestamp, a boolean indicating if the timestamp is in the past,
// // and prints relevant messages to the console.
// pub fn verify_timestamp(timestamp: u64, past: bool) -> Result<(), Error> {
//     // Constants representing the number of seconds in 100 and 10 years
//     let hundred_years_seconds = 3153600000;
//     let ten_years_seconds = 315360000;

//     // Obtain the current time as a duration since the UNIX epoch
//     // We work with Duration in order to add timestamps
//     let current_time = SystemTime::now()
//         .duration_since(UNIX_EPOCH)
//         .map_err(|e| format!("Failed to get current time: {}", e))?;

//     // Convert the timestamp to a duration since the UNIX epoch
//     let timestamp_time = UNIX_EPOCH + std::time::Duration::from_secs(timestamp);
//     let timestamp_duration = timestamp_time
//         .duration_since(UNIX_EPOCH)
//         .map_err(|e| format!("Failed to calculate duration: {}", e))?;

//     if past {
//         // Check if the timestamp is in the future
//         if timestamp_duration > current_time {
//             println!("{} is a timestamp in the future", timestamp);
//             std::process::exit(1);
//         // Check if the timestamp is more than 100 years in the past
//         } else if current_time - timestamp_duration
//             > std::time::Duration::from_secs(hundred_years_seconds)
//         {
//             println!(
//                 "{} is a timestamp more than 100 years in the past",
//                 timestamp
//             );
//         }
//     } else {
//         // Check if the timestamp is in the past
//         if timestamp_duration < current_time {
//             println!("{} is a timestamp in the past", timestamp);
//             std::process::exit(1);
//         // Check if the timestamp is more than 10 years in the future
//         } else if timestamp_duration - current_time
//             > std::time::Duration::from_secs(ten_years_seconds)
//         {
//             println!(
//                 "{} is a timestamp more than 10 years in the future",
//                 timestamp
//             );
//         }
//     }

//     Ok(())
// }

// saves a certificate
pub fn save_certificate(
    base_filename: &str,
    certificate: &str,
    signature: Signature,
) -> Result<String, Error> {
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
    let mut filename = base_filename.to_string();

    while file_exists(path, &filename)? {
        filename = format!("{}-{}", base_filename, filename_index);
        filename_index += 1;
    }

    let filename_with_path = format!("certs/created/{}", filename);

    // create signature json string
    let s_rx = cast::fq_to_dec_string(&signature.r_b8.x);
    let s_ry = cast::fq_to_dec_string(&signature.r_b8.y);
    let s_s = cast::fr_to_dec_string(&signature.s);
    let signature_json = format!(r#"{{"s":"{}", "rx":"{}", "ry":"{}"}}"#, s_s, s_rx, s_ry);

    // Open the file in write mode, creating it if it doesn't exist
    let mut file = File::create(filename_with_path.clone())
        .map_err(|e| format!("Unable to write file: {}", e))?;

    // Write the first string followed by a newline character
    [
        certificate.as_bytes(),
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
