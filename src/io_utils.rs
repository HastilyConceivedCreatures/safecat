/* Collection of IO functions for 
   saving, loading, and printing */

use babyjubjub_ark::PrivateKey;
use std::io::{self, Read, Write};
use std::fs::{File};

pub fn save_private_key(filename: &str, private_key: &PrivateKey) -> io::Result<()> {
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

    println!("");


    // ANSI escape codes for green color
    let green_color_code = "\x1b[32m";
    let reset_color_code = "\x1b[0m";

    // Notify after saving the private key into a file
    println!("Saved the new private key in {}{}{} file", green_color_code, filename, reset_color_code);

    Ok(())
}

pub fn load_private_key(filename: &str) -> io::Result<PrivateKey> {
    // Read the content of the file into a string
    let mut private_key_hex_string = String::new();
    File::open(filename)?.read_to_string(&mut private_key_hex_string)?;

    // Create a buffer to read the content into
    let mut numbers: [u8; 32] = [0; 32];

    // Parse the hex string into a numbers
    let key_array = hex::decode(private_key_hex_string.trim()).unwrap();
    numbers.copy_from_slice(&key_array);

    // let numbers_vec = numbers.to_vec();
    let numbers_vec: Vec<u8> = numbers.to_vec();
    let private_key: PrivateKey = PrivateKey::import(numbers_vec).unwrap();

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

pub fn bad_command(command: &str) {
    match command {
        "general" => {
            let my_str = include_str!("safecat.txt");
            print!("{my_str}");

            println!("Usage: safecat <generate|show|sign|verify> [--hash sha256|poseidon=default] [--format hex|detailed=default] [parameters]");
            println!("Ex., 'safecat sign --hash poseidon --format hex 'hello world'");
            },
        "generate" =>    
            println!("Usage: 'safecat generate' with no extra parameters"),
        "show" =>    
            println!("Usage: 'safecat show [--format hex|detailed=default]'"),
        "sign" =>
            println!("Usage: 'safecat sign [--hash sha256|poseidon=default] [--format hex|detailed=default] <message_to_sign>'"),
        "verify" =>
            println!("Usage: 'safecat verify [--hash sha256|poseidon=default] <message_to_verify> <signature> <public_key>'"),
        "message_too_long" =>
            println!("Message too long! The maximum message lengt with Poseidon hash is 16 characters"),
        _ => {
            println!("Usage: safecat <generate|show|sign|verify> [--hash sha256|poseidon=default] [--format hex|detailed=default] [parameters]");
            println!("Ex., 'safecat sign --hash poseidon --format hex 'hello world'");
            },
    }

    std::process::exit(1);
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