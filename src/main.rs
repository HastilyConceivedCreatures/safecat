mod cast; // module for casting between types
mod io_utils;
mod consts;

use ark_std::str::FromStr;
use babyjubjub_ark::{new_key, verify, Fq, Point, PrivateKey};
use ff_ce::PrimeField;
use poseidon_rs::{Fr as FrPoseidon, Poseidon};
use std::env;
use std::fs::{self};

use clap::{arg, Command}; // Command Line Argument Parser

fn main() {
    // Parse command-line arguments using the configured CLI structure
    let matches = cli().get_matches();

    // Match the subcommand and execute the corresponding logic
    match matches.subcommand() {
        Some(("generate", _)) => {
            generate()
        },
        Some(("show", sub_matches)) => {
            let format = sub_matches.get_one::<String>("format").expect("defaulted in clap");
            show(format.to_string())
        },
        Some(("sign", sub_matches)) => {
            let msg = sub_matches.get_one::<String>("MESSAGE").expect("required");
            let format = sub_matches.get_one::<String>("format").expect("defaulted in clap");
            let hash = sub_matches.get_one::<String>("hash").expect("defaulted in clap");
            println!(
                "Signing {}",
                msg
            );
            sign(msg.to_string(), hash.to_string(), format.to_string())
        },
        Some(("verify", sub_matches)) => {
            let msg = sub_matches.get_one::<String>("MESSAGE").expect("required").to_string();
            let signature = sub_matches.get_one::<String>("SIGNATURE").expect("required").to_string();
            let private_key = sub_matches.get_one::<String>("PUBLICKEY").expect("required").to_string();
            let hash = sub_matches.get_one::<String>("hash").expect("defaulted in clap").to_string();
            println!(
                "Verifying {}",
                msg
            );
            verify_signature(msg, signature, private_key, hash)
        },
        Some((_, _)) => {
            print!("unknown command, usage 'safecat <generate|show|sign|verify>'")
        },   
        None => todo!()
        }
}

// CLI configuration function
fn cli() -> Command {
    // Create the top-level 'safecat' command
    Command::new("safecat")
        .subcommand_required(true) // Specify that a subcommand is required
        .arg_required_else_help(true) // Ensure that at least one argument is required, or display help
        .allow_external_subcommands(true) // Allow external subcommands to be executed
        .subcommand(
            Command::new("generate")
                .about("Generates a private key") 
        )
        .subcommand(
            Command::new("show")
                .about("Shows keys")
                .arg(arg!(--"format" <FORMAT>)
                     .value_parser(["detailed", "hex"])
                     .require_equals(false)
                     .default_missing_value("detailed")
                     .default_value("detailed")
                )
        )
        .subcommand(
            Command::new("sign")
                .about("Sign a message using BabyJubJub")
                .arg(arg!(--"hash" <HASH>)
                     .value_parser(["poseidon", "sha256"])
                     .require_equals(false)
                     .default_missing_value("poseidon")
                     .default_value("poseidon")
                )
                .arg(arg!(--"format" <FORMAT>)
                     .value_parser(["detailed", "hex"])
                     .require_equals(false)
                     .default_missing_value("detailed")
                     .default_value("detailed")
                )
                .arg_required_else_help(true)
                .arg(arg!(<MESSAGE> "message")
                     .require_equals(true)
                )
        )
        .subcommand(
            Command::new("verify")
                .about("Verify a message using BabyJubJub")
                .arg(arg!(--"hash" <HASH>)
                     .value_parser(["poseidon", "sha256"])
                     .require_equals(false)
                     .default_missing_value("poseidon")
                     .default_value("poseidon")
                )
                .arg_required_else_help(true)
                .arg(arg!(<MESSAGE> "message")
                     .require_equals(true)
                )
                .arg(arg!(<SIGNATURE> "signature")
                     .require_equals(true)
                )
                .arg(arg!(<PUBLICKEY> "public key")
                     .require_equals(true)
                )
        )
}

// Generates a new private key, computes the corresponding public key, and saves them to file
fn generate() {
    // Initialize a random number generator
    let mut rng = rand::thread_rng();
 
    // Generate a new private key
    let private_key = new_key(&mut rng);

    // Compute the corresponding public key
    let public_key = private_key.public();

    // Save keys to files
    io_utils::save_private_key("priv.key", &private_key)
        .map_err(|err| println!("{:?}", err))
        .ok();
    io_utils::save_public_key("pub.key", public_key)
        .map_err(|err| println!("{:?}", err))
        .ok();
}

// Displays private and public keys based on the specified output format.
fn show(output_format: String) {
    // Check if private key file exists
    if !file_exists("priv.key") {
        println!("No key was generated yet.");
        return;
    }

    let private_key = io_utils::load_private_key("priv.key").unwrap();
    let public_key = private_key.public();

    if output_format == "detailed" {
        // Print private key
        print!("private key: ");
        io_utils::print_u8_array(&private_key.key, "dec");
        println!("");

        println!("public key Field X: {}", cast::fq_to_dec_string(&public_key.x));
        println!("public key Field Y: {}", cast::fq_to_dec_string(&public_key.y));
    } else if output_format == "hex" {
        // Print private key
        print!("private key: ");
        io_utils::print_u8_array(&private_key.key, "hex");
        println!("");

        // Print public key
        print!("public key: ");
        let hex_string_x = cast::fq_to_hex_string(&public_key.x);
        let hex_string_y = cast::fq_to_hex_string(&public_key.y);

        println!("{}{}", hex_string_x, hex_string_y);
    }
}

// Signs a message using BabyJubJub based on the specified hash algorithm and output format.
fn sign(message_to_sign_string: String, hash_algorithm: String, output_format: String) {
            if hash_algorithm == "poseidon"
                && message_to_sign_string.len() > consts::MAX_POSEIDON_PERMUTATION_LEN * consts::PACKED_BYTE_LEN
            {
                io_utils::bad_command("message_too_long");
            }

            // Check if private key file exists
            if !file_exists("priv.key") {
                println!("No key was generated yet.");
                return;
            }

            let private_key = io_utils::load_private_key("priv.key").unwrap();

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

// Verifies a message signature using BabyJubJub based on the specified hash algorithm.
fn verify_signature(message_to_verify_string: String, signature_string: String, public_key_hex_string: String , hash_algorithm: String) {
            println!("message_to_verify_string: {}", message_to_verify_string);
            println!("public_key_hex_string: {}", public_key_hex_string);
            println!("signature_string: {}", signature_string);

            if  hash_algorithm == "poseidon" &&
                message_to_verify_string.len() > consts::MAX_POSEIDON_PERMUTATION_LEN * consts::PACKED_BYTE_LEN
            {
                io_utils::bad_command("message_too_long");
            }

            let hash_fq = calculate_hash_fq(&message_to_verify_string, &hash_algorithm);

            // Create PublicKey and signature objects
            let public_key = cast::public_key_from_str(&public_key_hex_string).unwrap();
            let signature = cast::signature_from_str(&signature_string);

            let correct = verify(public_key, signature, hash_fq);

            println!("signature is {}", correct);
}

// Calculateד hash_fq based on hash_algorithm
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
        io_utils::bad_command("general");
    }

    hash_fq
}

// Checks if the file at the specified path exists
fn file_exists(file_path: &str) -> bool {
    fs::metadata(file_path).is_ok()
}

/// Test for the byte packing functionality
#[test]
fn byte_packing_test() {
    // Test case 1: Single field from 3 bytes
    let bytes: &[u8] = &[0x01, 0x02, 0x03];
    let fields = cast::bytes_to_fields(bytes);
    assert!(fields.len() == 1);
    assert!(fields[0] == Fq::from_str(&cast::hex_to_dec("0x010203")).unwrap());

    // Test case 2: Multiple fields from 64 bytes
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

/// Test for the Poseidon hash functionality
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

