mod cast;

use ark_std::str::FromStr;
use babyjubjub_ark::{new_key, verify, Fq, Point, PrivateKey};
use ff_ce::PrimeField;
use hex;
use poseidon_rs::{Fr as FrPoseidon, Poseidon};
use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};

const MAX_POSEIDON_PERMUTATION_LEN: usize = 16;
const PACKED_BYTE_LEN: usize = 31;

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
                                    if message_to_verify_options.is_some()
                                        || signature_options.is_some()
                                        || public_key_hex_options.is_some()
                                    {
                                        // More than three arguments for "verify" command
                                        bad_command("verify");
                                    } else {
                                        message_to_verify_options = Some(&args[i]);
                                    }
                                }
                                _ if i == args.len() - 2 => {
                                    if signature_options.is_some()
                                        || public_key_hex_options.is_some()
                                    {
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
                                _ => {}
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
            save_private_key("priv.key", &private_key)
                .map_err(|err| println!("{:?}", err))
                .ok();
            save_public_key("pub.key", public_key)
                .map_err(|err| println!("{:?}", err))
                .ok();
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

                println!("public key Field X: {}", cast::fq_to_dec_string(&public_key.x));
                println!("public key Field Y: {}", cast::fq_to_dec_string(&public_key.y));
            } else if output_format == "hex" {
                // Print private key
                print!("private key: ");
                print_u8_array(&private_key.key, "hex");
                println!("");

                // Print public key
                print!("public key: ");
                let hex_string_x = cast::fq_to_hex_string(&public_key.x);
                let hex_string_y = cast::fq_to_hex_string(&public_key.y);

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

            if hash_algorithm == "poseidon"
                && message_to_sign_string.len() > MAX_POSEIDON_PERMUTATION_LEN * PACKED_BYTE_LEN
            {
                bad_command("message_too_long");
            }

            // Check if private key file exists
            if !file_exists("priv.key") {
                println!("No key was generated yet.");
                return;
            }

            private_key = load_private_key("priv.key").unwrap();

            let hash_fq = calculate_hash_fq(&message_to_sign_string, &hash_algorithm);

            // Print the hash
            println!("message Hash: {}", cast::fq_to_dec_string(&hash_fq));

            // Sign the message
            let signature = private_key.sign(hash_fq).expect("Failed to sign message");

            if output_format == "detailed" {
                // Print signature
                println!("Signature: R.X: {}", cast::fq_to_dec_string(&signature.r_b8.x));
                println!("Signature: R.Y: {}", cast::fq_to_dec_string(&signature.r_b8.y));
                println!("Signature: S: {}", cast::fr_to_dec_string(&signature.s));
            } else if output_format == "hex" {
                // change signature variables to hex
                let signature_x_hex = cast::fq_to_hex_string(&signature.r_b8.x);
                let signature_y_hex = cast::fq_to_hex_string(&signature.r_b8.y);
                let signature_s_hex = cast::fr_to_hex_string(&signature.s);

                println!(
                    "Signature: {}{}{}",
                    signature_x_hex, signature_y_hex, signature_s_hex
                );
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

            if hash_algorithm == "poseidon"
                && message_to_verify_string.len() > MAX_POSEIDON_PERMUTATION_LEN * PACKED_BYTE_LEN
            {
                bad_command("message_too_long");
            }

            let hash_fq = calculate_hash_fq(&message_to_verify_string, &hash_algorithm);

            // Create PublicKey and signature objects
            let public_key = cast::public_key_from_str(&public_key_hex_string).unwrap();
            let signature = cast::signature_from_str(&signature_string);

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

fn save_public_key(filename: &str, public_key: Point) -> io::Result<()> {
    let mut file = File::create(filename)?;

    let x_string_hex = cast::fq_to_hex_string(&public_key.x);
    let y_string_hex = cast::fq_to_hex_string(&public_key.y);

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

fn print_u8_array(arr: &[u8], format: &str) {
    for &element in arr {
        if format == "hex" {
            print!("{:02x?}", element);
        } else if format == "dec" {
            print!("{:?}", element);
        }
    }
}


#[test]
fn byte_packing_test() {
    let bytes: &[u8] = &[0x01, 0x02, 0x03];
    let fields = cast::bytes_to_fields(bytes);
    assert!(fields.len() == 1);
    assert!(fields[0] == Fq::from_str(&cast::hex_to_dec("0x010203")).unwrap());

    let bytes: Vec<u8> = (0..64).collect();
    let fields = cast::bytes_to_fields(&bytes);
    assert!(fields.len() == 3);
    assert!(fields[0] == Fq::from_str(&cast::hex_to_dec("0x0001")).unwrap());
    assert!(
        fields[1]
            == Fq::from_str(&cast::hex_to_dec(
                "0x02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
            ))
            .unwrap()
    );
    assert!(
        fields[2]
            == Fq::from_str(&cast::hex_to_dec(
                "0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            ))
            .unwrap()
    );
}

// Function to calculate hash_fq based on hash_algorithm
fn calculate_hash_fq(message_to_verify_string: &str, hash_algorithm: &str) -> Fq {
    let mut hash_fq = Fq::from_str("0").unwrap();

    if hash_algorithm == "poseidon" {
        let bytes = message_to_verify_string.as_bytes();

        // Pack the message bytes into right-aligned 31-byte chunks
        let fr_vector: Vec<FrPoseidon> = cast::bytes_to_fields(bytes)
            .iter()
            .map(|&b| FrPoseidon::from_str(&b.to_string()).unwrap())
            .collect();

        // Create a Poseidon hash function
        let poseidon = Poseidon::new();

        // // Hash the input vector
        let poseidon_hash = poseidon.hash(fr_vector).unwrap();

        // turn into a string
        let mut poseidon_hash_str = poseidon_hash.into_repr().to_string();
        poseidon_hash_str = cast::hex_to_dec(&poseidon_hash_str);

        // turn the hash into Fq
        hash_fq = Fq::from_str(&poseidon_hash_str).unwrap();
    } else if hash_algorithm == "sha256" {
        //  hash the message
        let hashed_sha256_message_string = cast::hash256_as_string(message_to_verify_string);

        // turn the hash into Fq
        hash_fq = Fq::from_str(&hashed_sha256_message_string).unwrap();
    } else {
        bad_command("general");
    }

    hash_fq
}

#[test]
fn test_poseidon_hash() {
    let msg = "This is a run-through of the Poseidon permutation function.";
    let hash = calculate_hash_fq(msg, "poseidon");
    assert!(
        hash == Fq::from_str(&cast::hex_to_dec(
            "0x0b5de89054f5ff651f919eb397f4a125e9ba2aebd175dd809fe8fd02569d8087"
        ))
        .unwrap()
    );
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

fn file_exists(file_path: &str) -> bool {
    fs::metadata(file_path).is_ok()
}

