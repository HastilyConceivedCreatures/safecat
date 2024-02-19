use std::env;
use std::fs::{ self, File};
use std::io::{self, Read, Write};
use sha2::{Digest, Sha256};
use ark_std::str::FromStr;
use babyjubjub_ark::{PrivateKey, Point, Signature, new_key, verify, Fq, Fr};
use num_bigint::BigUint;
use hex;
use poseidon_rs::{Fr as FrPoseidon, Poseidon};
use ff_ce::PrimeField;
use num::{BigInt, Num};

fn main() {
    // init private key to zero
    let private_key: PrivateKey;
    let public_key: Point;

    let args: Vec<String> = env::args().collect();

    // Verify if the correct number of arguments is provided
    if args.len() < 2 {
        bad_command("general");
    }

    // Extract the command
    let command = &args[1];

    let mut output_format = "detailed";
    let mut hash_algorithm = "poseidon";

    let mut message_to_sign_options: Option<&str> = None;
    let mut message_to_verify_options: Option<&str> = None;
    let mut signature_options: Option<&str> = None;
    let mut public_key_hex_options: Option<&str> = None;

    // Check if the command is valid
    match command.as_str() {
        "generate" | "show" | "sign" | "verify" => {

            // Check for optional flags
            for i in 2..args.len() {
                match args[i].as_str() {
                    "--format" => {
                        if i + 1 < args.len() {
                            output_format = &args[i + 1];
                            if command != "show" && command != "sign" {
                                // Invalid command
                                bad_command("general");
                            }
                        }
                    }
                    "--hash" => {
                        if i + 1 < args.len() {
                            hash_algorithm = &args[i + 1];
                            if command != "sign" && command != "verify" {
                                // Invalid command
                                bad_command("general");
                            }
                        } 
                    }
                    _ => {
                        // Check for "sign" command and assume it's the message to sign
                        if command == "sign" {
                            if message_to_sign_options.is_some() {
                                // More than one argument for "sign" command
                                bad_command("sign");
                            } else {
                                if i == args.len() - 1 {
                                    message_to_sign_options = Some(&args[i]);
                                }
                            }
                        }
                        // Check for "verify" command and assign values to the variables
                        else if command == "verify" {
                            match i {
                                _ if i == args.len() - 3 => {
                                    if message_to_verify_options.is_some() || signature_options.is_some() || public_key_hex_options.is_some() {
                                        // More than three arguments for "verify" command
                                        bad_command("verify");
                                    } else {
                                        message_to_verify_options = Some(&args[i]);
                                    }
                                }
                                _ if i == args.len() - 2 => {
                                    if signature_options.is_some() || public_key_hex_options.is_some() {
                                        // More than three arguments for "verify" command
                                        bad_command("verify");
                                    } else {
                                        signature_options = Some(&args[i]);
                                    }
                                }
                                _ if i == args.len() - 1 => {
                                    if public_key_hex_options.is_some() {
                                        // More than three arguments for "verify" command
                                        bad_command("verify");
                                    } else {
                                        public_key_hex_options = Some(&args[i]);
                                    }
                                }
                                _ => {                                    
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {
            // Invalid command
            bad_command("general");
        }
    }

    match command.as_str() {
        "generate" => {
            if args.len() != 2 {
                bad_command("generate");
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
            // Check if private key file exists
            if !file_exists("priv.key") {
                println!("No key was generated yet.");
                return;
            }

            private_key = load_private_key("priv.key").unwrap();
            public_key = private_key.public();

            if output_format == "detailed" {
                // Print private key
                print!("private key: ");
                print_u8_array(&private_key.key, "dec");
                println!("");

                println!("public key Field X: {}", fq_to_dec_string(&public_key.x));
                println!("public key Field Y: {}", fq_to_dec_string(&public_key.y));
            } else if output_format == "hex" {
                // Print private key
                print!("private key: ");
                print_u8_array(&private_key.key, "hex");
                println!("");

                // Print public key
                print!("public key: ");
                let hex_string_x = fq_to_hex_string(&public_key.x);
                let hex_string_y = fq_to_hex_string(&public_key.y);

                println!("{}{}", hex_string_x, hex_string_y);
            } else {
                bad_command("show");
            }

        }
        "sign" => {
            if args.len() == 2 {
                bad_command("sign");
            }

            // unwrap parameters
            let message_to_sign_string = message_to_sign_options.unwrap();

            // Check if private key file exists
            if !file_exists("priv.key") {
                println!("No key was generated yet.");
                return;
            }

            private_key = load_private_key("priv.key").unwrap();

            let hash_fq = calculate_hash_fq(&message_to_sign_string, &hash_algorithm);

            // Print the hash
            println!("message Hash: {}", fq_to_dec_string(&hash_fq));

            // Sign the message
            let signature = private_key.sign(hash_fq).expect("Failed to sign message");

            if output_format == "detailed" {
                // Print signature
                println!("Signature: R.X: {}", fq_to_dec_string(&signature.r_b8.x));
                println!("Signature: R.Y: {}", fq_to_dec_string(&signature.r_b8.y));
                println!("Signature: S: {}", fr_to_dec_string(&signature.s));
            } else if output_format == "hex" {
                // change signature variables to hex
                let signature_x_hex = fq_to_hex_string(&signature.r_b8.x);
                let signature_y_hex = fq_to_hex_string(&signature.r_b8.y);
                let signature_s_hex = fr_to_hex_string(&signature.s);

                println!("Signature: {}{}{}", signature_x_hex, signature_y_hex, signature_s_hex);
            }

        }
        "verify" => {
            if args.len() == 2 {
                bad_command("verify");
            }

            // unwrap parameters
            let message_to_verify_string = message_to_verify_options.unwrap();
            let public_key_hex_string = public_key_hex_options.unwrap();
            let signature_string = signature_options.unwrap();

            let hash_fq = calculate_hash_fq(&message_to_verify_string, &hash_algorithm);

            // Create PublicKey and signature objects
            let public_key = public_key_from_str(&public_key_hex_string).unwrap();
            let signature = signature_from_str(&signature_string);

            let correct = verify(public_key, signature, hash_fq);

            println!("signature is {}", correct);

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


fn print_u8_array(arr: &[u8], format: &str) {
    for &element in arr {
        if format == "hex" {
            print!("{:02x?}", element);
        } else if format == "dec" {
            print!("{:?}", element);
        }
    }
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

pub fn fq_to_dec_string(num: &Fq) -> String {
    // convert to a decimal string
    let num_string = num.to_string();

    // Parse the decimal string into a hex
    let num_decimal = BigUint::parse_bytes(num_string.as_bytes(), 10).unwrap();

    // return the hex string
    num_decimal.to_string()
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

pub fn fr_to_dec_string(num: &Fr) -> String {
    // convert to a decimal string
    let num_string = num.to_string();

    // Parse the decimal string into a hex
    let num_decimal = BigUint::parse_bytes(num_string.as_bytes(), 10).unwrap();

    // return the hex string
    num_decimal.to_string()
}

pub fn hash256_as_string(message: &str) -> String {
    // create hash of the message
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let hashed_message = hasher.finalize();


    //Convert the hash result to a BigInt<4> -> hex string -> fq
    let hashed_message_bigint = hash_to_bigint(&hashed_message[..]);
    let hashed_message_string = hashed_message_bigint.to_str_radix(10);

    hashed_message_string
}

pub fn hash_as_hex_string(message: &String) -> String {
    // create hash of the message
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let hashed_message = hasher.finalize();


    //Convert the hash result to a BigInt<4> -> hex string -> fq
    let hashed_message_bigint = hash_to_bigint(&hashed_message[..]);
    let hashed_hex_message_string = format!("{:0>64x}", hashed_message_bigint);

    hashed_hex_message_string
}

fn convert_hex_to_dec(hex_str: &str) -> String {
    let hex_value = if hex_str.starts_with("0x") {
        &hex_str[2..] // Remove the '0x' prefix
    } else {
        hex_str
    };

    BigInt::from_str_radix(hex_value, 16)
        .map(|dec_value| dec_value.to_string())
        .unwrap_or_else(|_| String::from("Invalid hex number"))
}

// Function to calculate hash_fq based on hash_algorithm
fn calculate_hash_fq(message_to_verify_string: &str, hash_algorithm: &str) -> Fq {
    let mut hash_fq = Fq::from_str("0").unwrap();

    if hash_algorithm == "poseidon" {
        let bytes = message_to_verify_string.as_bytes();

        // Convert each byte into an element of the finite field
        let fr_vector: Vec<FrPoseidon> = bytes.iter().map(|&b| FrPoseidon::from_str(&b.to_string()).unwrap()).collect();

        // Create a Poseidon hash function
        let poseidon = Poseidon::new();

        // // Hash the input vector
        let poseidon_hash = poseidon.hash(fr_vector).unwrap();

        // turn into a string
        let mut poseidon_hash_str = poseidon_hash.into_repr().to_string();
        poseidon_hash_str = convert_hex_to_dec(&poseidon_hash_str);

        // turn the hash into Fq
        hash_fq = Fq::from_str(&poseidon_hash_str).unwrap();
    } else if hash_algorithm == "sha256" {
        //  hash the message
        let hashed_sha256_message_string = hash256_as_string(message_to_verify_string);

        // turn the hash into Fq
        hash_fq = Fq::from_str(&hashed_sha256_message_string).unwrap();
    } else {
        bad_command("general");
    }

    hash_fq
}

pub fn bad_command(command: &str) {
    match command {
        "general" => {
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
        _ => {
            println!("Usage: safecat <generate|show|sign|verify> [--hash sha256|poseidon=default] [--format hex|detailed=default] [parameters]");
            println!("Ex., 'safecat sign --hash poseidon --format hex 'hello world'");
            },
    }
    
    std::process::exit(1);
}

fn file_exists(file_path: &str) -> bool {
    fs::metadata(file_path).is_ok()
}