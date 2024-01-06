use std::env;
use std::fs::{ self, File};
use std::io::{self, Read, Write};
use sha2::{Digest, Sha256};
use ark_std::str::FromStr;
use babyjubjub_ark::{PrivateKey, Point, Signature, new_key, verify, Fq, Fr};
use num_bigint::BigUint;
use hex;
use num::Num;

fn main() {
    // init private key to zero
    let private_key: PrivateKey;
    let public_key: Point;

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <command> [filename]", args[0]);
        return;
    }

    let command = &args[1];

    match command.as_str() {
        "generate" => {
            if args.len() != 2 {
                println!("Usage: '{} generate' with no extra parameters", args[0]);
                return;
            }

            // Initialize a random number generator 
            let mut rng = rand::thread_rng();

            // Generate a new private key
            private_key = new_key(&mut rng);

            // Compute the corresponding public key
            public_key = private_key.public();

            // Save keys to files
            save_private_key("priv.key", &private_key).map_err(|err| println!("{:?}", err)).ok();
            save_public_key("pub.key", public_key).map_err(|err| println!("{:?}", err)).ok();
        }
        "show" => {
            if args.len() != 2 {
                println!("Usage: '{} show' with no extra parameters", args[0]);
                return;
            }

            // Check if private key file exists
            if !file_exists("priv.key") {
                println!("No key was generated yet.");
                return;
            }

            private_key = load_private_key("priv.key").unwrap();
            public_key = private_key.public();

            // Print private key
            print!("private key: ");
            print_u8_array(&private_key.key);
            println!("");

            // Print public key
            print!("public key: ");
            let hex_string_x = fq_to_hex_string(&public_key.x);
            let hex_string_y = fq_to_hex_string(&public_key.y);

            println!("{}{}", hex_string_x, hex_string_y);
        }
        "sign" => {
            if args.len() != 3 {
                println!("Usage: {} sign <message_to_sign>", args[0]);
                return;
            }

            // Check if private key file exists
            if !file_exists("priv.key") {
                println!("No key was generated yet.");
                return;
            }

            private_key = load_private_key("priv.key").unwrap();
            let message = &args[2];

            //  hash the message
            let hashed_message_string = hash_as_string(&message);
            let hashed_message_fq = Fq::from_str(&hashed_message_string).unwrap();

            // Sign the message
            let signature = private_key.sign(hashed_message_fq).expect("Failed to sign message");

            // Print signature
            let signature_x_hex = fq_to_hex_string(&signature.r_b8.x);
            let signature_y_hex = fq_to_hex_string(&signature.r_b8.y);
            let signature_s_hex = fr_to_hex_string(&signature.s);

            println!("Signature: {}{}{}", signature_x_hex, signature_y_hex, signature_s_hex);
        }
        "verify" => {
            if args.len() != 5 {
                println!("Usage: {} verify <message_to_verify> <signature> <public_key>", args[0]);
                return;
            }

            let message = &args[2];
            let signature_string = &args[3];
            let public_key_hex_string = &args[4];

            // Create PublicKey object
            let public_key = public_key_from_str(&public_key_hex_string).unwrap();
            let signature = signature_from_str(&signature_string);

            //  hash the message
            let hashed_message_string = hash_as_string(&message);
            let hashed_message_fq = Fq::from_str(&hashed_message_string).unwrap();

            let correct = verify(public_key, signature, hashed_message_fq);

            println!("signature it {}", correct);

        }
        _ => {
            println!("Unknown command: {}", command);
        }
    }
}

fn save_private_key(filename: &str, private_key: &PrivateKey) -> io::Result<()> {
    print!("private_key:");

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

    Ok(())
}

fn save_public_key(filename: &str, public_key: Point)  -> io::Result<()> {
    let mut file = File::create(filename)?;

    let x_string_hex = fq_to_hex_string(&public_key.x);
    let y_string_hex = fq_to_hex_string(&public_key.y);
    
    println!("Public key: {}{}", x_string_hex, y_string_hex);
    
    write!(file, "{}{}", x_string_hex, y_string_hex).unwrap();
    
    Ok(())
}

fn load_private_key(filename: &str) -> io::Result<PrivateKey> {
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

fn public_key_from_str(key_string_hex: &str) -> io::Result<Point> {
    // Split the hex string into x and y parts
    let (x_string_hex, y_string_hex) = key_string_hex.split_at(64);

    // Parse hex strings into BigUint
    let x_decimal = BigUint::from_str_radix(x_string_hex, 16).unwrap();
    let y_decimal = BigUint::from_str_radix(y_string_hex, 16).unwrap();

    // Convert BigUint to Fq
    let x = Fq::from(x_decimal);
    let y = Fq::from(y_decimal);

    Ok(Point { x, y })
}

fn signature_from_str(signature_string_hex: &str) -> Signature {
    // Split the string at indices 64 and 128
    let (x_string_hex, temp) = signature_string_hex.split_at(64);
    let (y_string_hex, s_string_hex) = temp.split_at(64);

    // Parse hex strings into BigUint
    let x_decimal = BigUint::from_str_radix(x_string_hex, 16).unwrap();
    let y_decimal = BigUint::from_str_radix(y_string_hex, 16).unwrap();
    let s_decimal = BigUint::from_str_radix(s_string_hex, 16).unwrap();

    // Convert BigUint to Fq
    let x = Fq::from(x_decimal);
    let y = Fq::from(y_decimal);
    let s = Fr::from(s_decimal);

    let r_b8 = Point { x, y };

    Signature { r_b8, s}
}


fn print_u8_array(arr: &[u8]) {
    for &element in arr {
        print!("{:02x?}", element);
    }
}

fn file_exists(file_path: &str) -> bool {
    fs::metadata(file_path).is_ok()
}

pub fn hash_to_bigint(hash: &[u8]) -> BigUint {
    // Reverse the bytes because BigUint uses little-endian order
    let reversed_hash: Vec<u8> = hash.iter().rev().cloned().collect();

    // Create a BigUint from the reversed hash bytes
    BigUint::from_bytes_le(&reversed_hash)
}

pub fn fq_to_hex_string(num: &Fq) -> String {
    // convert to a decimal string
    let num_string = num.to_string();

    // Parse the decimal string into a hex
    let num_decimal = BigUint::parse_bytes(num_string.as_bytes(), 10).unwrap();
    let num_hex_string = format!("{:0>64x}", num_decimal);

    // return the hex string
    num_hex_string
}

pub fn fr_to_hex_string(num: &Fr) -> String {
    // convert to a decimal string
    let num_string = num.to_string();

    // Parse the decimal string into a hex
    let num_decimal = BigUint::parse_bytes(num_string.as_bytes(), 10).unwrap();
    let num_hex_string = format!("{:0>64x}", num_decimal);

    // return the hex string
    num_hex_string
}

pub fn hash_as_string(message: &String) -> String {
    // create hash of the message
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let hashed_message = hasher.finalize();

    //Convert the hash result to a BigInt<4> -> hex string -> fq
    let hashed_message_bigint = hash_to_bigint(&hashed_message[..]);
    let hashed_message_string = hashed_message_bigint.to_str_radix(10);

    hashed_message_string
}