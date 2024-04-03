mod cast; // module for casting between types
mod consts;
mod io_utils;

use ark_std::str::FromStr;
use babyjubjub_ark::{new_key, verify, Fq, Signature};
use ff_ce::PrimeField;
use poseidon_rs::{Fr as FrPoseidon, Poseidon};
use poseidon_ark::{Poseidon as PoseidonArk};
use clap::{arg, Command}; // Command Line Argument Parser

pub(crate) type Error = Box<dyn std::error::Error>;

fn main() -> Result<(), Error> {
    // Parse command-line arguments using the configured CLI structure
    let matches = cli().get_matches();

    // Match the subcommand and execute the corresponding logic
    match matches.subcommand() {
        Some(("generate", _)) => generate("priv.key")?,
        Some(("show-keys", sub_matches)) => {
            let format = sub_matches
                .get_one::<String>("format")
                .expect("defaulted in clap");
            show_keys(format.to_string())?
        }
        Some(("sign", sub_matches)) => {
            let msg = sub_matches.get_one::<String>("MESSAGE").expect("required");
            let format = sub_matches
                .get_one::<String>("format")
                .expect("defaulted in clap");
            let hash = sub_matches
                .get_one::<String>("hash")
                .expect("defaulted in clap");
            println!("Signing {}", msg);
            sign(msg.to_string(), hash.to_string(), format.to_string())
        }
        Some(("verify", sub_matches)) => {
            let msg = sub_matches
                .get_one::<String>("MESSAGE")
                .expect("required")
                .to_string();
            let signature = sub_matches
                .get_one::<String>("SIGNATURE")
                .expect("required")
                .to_string();
            let private_key = sub_matches
                .get_one::<String>("PUBLICKEY")
                .expect("required")
                .to_string();
            let hash = sub_matches
                .get_one::<String>("hash")
                .expect("defaulted in clap")
                .to_string();
            println!("Verifying {}", msg);
            verify_signature(msg, signature, private_key, hash)?
        }
        Some(("assert", sub_matches)) => {
            let public_key = sub_matches
                .get_one::<String>("PUBLICKEY")
                .expect("required")
                .to_string();
            let cert_type = *sub_matches.get_one("TYPE").expect("required");
            let expiration = *sub_matches.get_one("EXPIRATION").expect("required");
            let birth = *sub_matches.get_one("BIRTH").expect("required");
            let format = sub_matches
                .get_one::<String>("format")
                .expect("defaulted in clap")
                .to_string();
            assert(
                public_key,
                cert_type,
                expiration,
                birth,
                "poseidon".to_string(),
                format,
            )?;
        }
        Some(("show-certs", sub_matches)) => {
            let certificates_folder = sub_matches
                .get_one::<String>("CERTIFICATES_FOLDER")
                .expect("required")
                .to_string();

            let certificates_folder_path;
            if certificates_folder == "created" {
                certificates_folder_path = "certs/created";
            } else {
                certificates_folder_path = "certs/received"
            }
            io_utils::show_certs(certificates_folder_path)
                .map_err(|e| format!("Error showing certificates: {}", e))?;
        }
        Some((_, _)) => {
            println!("unknown command, For more information, try '--help'.")
        }
        None => todo!(),
    }

    Ok(())
}

// CLI configuration function
fn cli() -> Command {
    let safecat_ascii = include_str!("safecat.txt");

    // Create the top-level 'safecat' command
    Command::new("safecat")
        .about(safecat_ascii)
        .subcommand_required(true) // Specify that a subcommand is required
        .arg_required_else_help(true) // Ensure that at least one argument is required, or display help
        .subcommand(Command::new("generate").about("Generates a private key"))
        .subcommand(
            Command::new("show-keys").about("Shows keys").arg(
                arg!(--"format" <FORMAT>)
                    .value_parser(["detailed", "hex"])
                    .require_equals(false)
                    .default_missing_value("detailed")
                    .default_value("detailed"),
            ),
        )
        .subcommand(
            Command::new("sign")
                .about("Sign a message using BabyJubJub")
                .arg(
                    arg!(--"hash" <HASH>)
                        .value_parser(["poseidon", "sha256"])
                        .require_equals(false)
                        .default_missing_value("poseidon")
                        .default_value("poseidon"),
                )
                .arg(
                    arg!(--"format" <FORMAT>)
                        .value_parser(["detailed", "hex"])
                        .require_equals(false)
                        .default_missing_value("detailed")
                        .default_value("detailed"),
                )
                .arg_required_else_help(true)
                .arg(arg!(<MESSAGE> "message").require_equals(true)),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify a message using BabyJubJub")
                .arg(
                    arg!(--"hash" <HASH>)
                        .value_parser(["poseidon", "sha256"])
                        .require_equals(false)
                        .default_missing_value("poseidon")
                        .default_value("poseidon"),
                )
                .arg_required_else_help(true)
                .arg(arg!(<MESSAGE> "message").require_equals(true))
                .arg(arg!(<SIGNATURE> "signature").require_equals(true))
                .arg(arg!(<PUBLICKEY> "public key").require_equals(true)),
        )
        .subcommand(
            Command::new("assert")
                .about("Creates a certificate for an assertion")
                .arg_required_else_help(true)
                .arg(arg!(<PUBLICKEY> "public key").require_equals(true))
                .arg(
                    arg!(<TYPE> "certificate type")
                        .require_equals(true)
                        .value_parser(clap::value_parser!(u32)),
                )
                .arg(
                    arg!(<EXPIRATION> "expiration date")
                        .require_equals(true)
                        .value_parser(clap::value_parser!(u64)),
                )
                .arg(
                    arg!(<BIRTH> "birth date")
                        .require_equals(true)
                        .value_parser(clap::value_parser!(u64)),
                )
                .arg(
                    arg!(--"format" <FORMAT>)
                        .value_parser(["json", "field"])
                        .require_equals(false)
                        .default_missing_value("json")
                        .default_value("json"),
                ),
        )
        .subcommand(
            Command::new("show-certs")
                .about("Show existing certificates")
                .arg_required_else_help(true)
                .arg(
                    arg!(<CERTIFICATES_FOLDER> "certificates folder")
                        .value_parser(["created", "received"])
                        .require_equals(true),
                ),
        )
}

// Generates a new private key and saves it to file
fn generate(privatekey_filename: &str) -> Result<(), Error> {
    // Initialize a random number generator
    let mut rng = rand::thread_rng();

    // Generate a new private key
    let private_key = new_key(&mut rng);

    // Save keys to files
    io_utils::save_private_key(privatekey_filename, &private_key)?;

    Ok(())
}

// Displays private and public keys based on the specified output format.
fn show_keys(output_format: String) -> Result<(), Error> {
    // Check if private key file exists
    if !io_utils::file_exists("","priv.key")? {
        return Err("No key has been generated yet.".into());
    }

    let private_key = io_utils::load_private_key("priv.key")?;
    let public_key = private_key.public();

    if output_format == "detailed" {
        // Print private key
        print!("private key: ");
        io_utils::print_u8_array(&private_key.key, "dec");
        println!("");

        println!(
            "public key Field X: {}",
            cast::fq_to_dec_string(&public_key.x)
        );
        println!(
            "public key Field Y: {}",
            cast::fq_to_dec_string(&public_key.y)
        );
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

    Ok(())
}

// Signs a message using BabyJubJub based on the specified hash algorithm and output format.
fn sign(message_to_sign_string: String, hash_algorithm: String, output_format: String) {
    // Sign the message
    let (signature, hash_fq) = match sign_message(message_to_sign_string, hash_algorithm) {
        Ok((signature, fq)) => (signature, fq),
        Err(err_msg) => {
            println!("Error: {}", err_msg);
            return;
        }
    };

    // Print the hash
    println!("message Hash: {}", cast::fq_to_dec_string(&hash_fq));

    if output_format == "detailed" {
        // Print signature
        println!(
            "Signature: R.X: {}",
            cast::fq_to_dec_string(&signature.r_b8.x)
        );
        println!(
            "Signature: R.Y: {}",
            cast::fq_to_dec_string(&signature.r_b8.y)
        );
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
fn verify_signature(
    message_to_verify_string: String,
    signature_string: String,
    public_key_hex_string: String,
    hash_algorithm: String,
) -> Result<(), Error> {
    println!("message_to_verify_string: {}", message_to_verify_string);
    println!("public_key_hex_string: {}", public_key_hex_string);
    println!("signature_string: {}", signature_string);

    // calculate max message length for Poesidon hash
    const MAX_POSEIDON_MESSAGE_LEN: usize =
        consts::MAX_POSEIDON_PERMUTATION_LEN * consts::PACKED_BYTE_LEN;

    if hash_algorithm == "poseidon" && message_to_verify_string.len() > MAX_POSEIDON_MESSAGE_LEN {
        println!(
            "Message too long! Maximum message length with Poseidon  is {} characters",
            MAX_POSEIDON_MESSAGE_LEN
        );
        std::process::exit(1);
    }

    let hash_fq = calculate_hash_fq(&message_to_verify_string, &hash_algorithm);

    // Create PublicKey and signature objects
    let public_key = cast::public_key_from_str(&public_key_hex_string)?;
    let signature = cast::signature_from_str(&signature_string)?;

    let correct = verify(public_key, signature, hash_fq);

    println!("signature is {}", correct);

    Ok(())
}

// Creates a certificate
fn assert(
    public_key_str: String,
    cert_type: u32,
    expiration_date: u64,
    birthdate: u64,
    hash_algorithm: String,
    format: String,
) -> Result<(), Error> {
    // validate public key input and split it into x and y
    let (pubic_key_x_str, pubic_key_y_str) = io_utils::split_hex_string(&public_key_str);

    // validate expiration date is in the future
    io_utils::verify_timestamp(expiration_date, false)?;

    // validate expiration date is in the past
    io_utils::verify_timestamp(birthdate, true)?;

    // json of each certificate component
    let public_key_x_json = format!(r#""x":"{}""#, pubic_key_x_str);
    let public_key_y_json = format!(r#""y":"{}""#, pubic_key_y_str);
    let cert_type_json = format!(r#""type":{}"#, cert_type);
    let expdate_json = format!(r#""expdate":{}"#, expiration_date);
    let bdate_json = format!(r#""bdate":{}"#, birthdate);

    // inner part of certificate json
    let cert_json_inner = format!(
        r#"{},{},{},{},{}"#,
        public_key_x_json, public_key_y_json, cert_type_json, expdate_json, bdate_json
    );
    let cert_json = format!(r#"{{{}}}"#, cert_json_inner);

    let signature : Signature;

    if format == "field" {
        let public_key_x_dec = cast::hex_to_dec(&pubic_key_x_str)?;
        let public_key_y_dec = cast::hex_to_dec(&pubic_key_y_str)?;
        let public_key_x_fq = Fq::from_str(&*public_key_x_dec).unwrap();
        let public_key_y_fq = Fq::from_str(&*public_key_y_dec).unwrap();

        let expiration_date_fq = Fq::from(expiration_date);
        let cert_type_fq = Fq::from(cert_type);
        let birthdate_fq = Fq::from(birthdate);

        let cert_field_vec = vec![public_key_x_fq, public_key_y_fq, expiration_date_fq, cert_type_fq, birthdate_fq];

        let poseidon_ark = PoseidonArk::new();
        let hash_fq = poseidon_ark.hash(cert_field_vec)?;

        signature = sign_hash(hash_fq)?;
    } else {
        // Sign the certificate
        (signature, _) = match sign_message(cert_json.clone(), hash_algorithm) {
            Ok((signature, fq)) => Ok((signature, fq)),
            Err(err) => Err(err),
        }?;
    }

    // save certificates to file
    let base_filename = format!("{}-{}", public_key_str, cert_type);
    let filename = io_utils::save_certificate(&base_filename, &cert_json, signature);

    println!("The certificate was saved to file: {}", filename?);

    Ok(())
}

// Calculate hash_fq based on hash_algorithm
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
        poseidon_hash_str = cast::hex_to_dec(&poseidon_hash_str).unwrap();

        // turn the hash into Fq
        hash_fq = Fq::from_str(&poseidon_hash_str).unwrap();
    } else if hash_algorithm == "sha256" {
        //  hash the message
        let hashed_sha256_message_string = cast::hash256_as_string(message_to_verify_string);

        // turn the hash into Fq
        hash_fq = Fq::from_str(&hashed_sha256_message_string).unwrap();
    }

    hash_fq
}

// Hashes a message and then signs it. Returns the signature and the hash.
fn sign_message(
    message_to_sign_string: String,
    hash_algorithm: String,
) -> Result<(Signature, Fq), Error> {
    // calculate max message length for Poseidon hash
    const MAX_POSEIDON_MESSAGE_LEN: usize =
        consts::MAX_POSEIDON_PERMUTATION_LEN * consts::PACKED_BYTE_LEN;

    if hash_algorithm == "poseidon" && message_to_sign_string.len() > MAX_POSEIDON_MESSAGE_LEN {
        println!(
            "Message too long! Maximum message length with Poseidon  is {} characters",
            MAX_POSEIDON_MESSAGE_LEN
        );
    }

    let hash_fq = calculate_hash_fq(&message_to_sign_string, &hash_algorithm);

    // Check if private key file exists
    if !io_utils::file_exists("", "priv.key")? {
        return Err("No key has been generated yet.".into());
    }

    let private_key = io_utils::load_private_key("priv.key")?;

    // Sign the message
    let signature: Signature = private_key
        .sign(hash_fq)
        .map_err(|e| format!("Failed to sign message: {}", e))?;

    Ok((signature, hash_fq))
}

// Signs a hash. Returns the signature.
fn sign_hash(
    hash_fq: Fq
) -> Result<Signature, Error> {
    // Check if private key file exists
    if !io_utils::file_exists("","priv.key")? {
        return Err("No key has been generated yet.".into());
    }

    // Load private key from file
    let private_key = io_utils::load_private_key("priv.key")?;

    // Sign the hash
    let signature: Signature = private_key
        .sign(hash_fq)
        .map_err(|e| format!("Failed to sign message: {}", e))?;

    Ok(signature)
}

/// Test for the byte packing functionality
#[test]
fn byte_packing_test() -> Result<(), Error> {
    // Test case 1: Single field from 3 bytes
    let bytes: &[u8] = &[0x01, 0x02, 0x03];
    let fields = cast::bytes_to_fields(bytes);
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0], Fq::from_str(&cast::hex_to_dec("0x010203").unwrap()).unwrap());

    // Test case 2: Multiple fields from 64 bytes
    let bytes: Vec<u8> = (0..64).collect();
    let fields = cast::bytes_to_fields(&bytes);
    assert_eq!(fields.len(), 3);
    assert_eq!(Ok(fields[0]), Fq::from_str(&cast::hex_to_dec("0x0001")?));
    assert_eq!(Ok(fields[1]), Fq::from_str(&cast::hex_to_dec(
        "0x02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    )?));
    assert_eq!(Ok(fields[2]), Fq::from_str(&cast::hex_to_dec(
        "0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    )?));
    Ok(())
}

/// Test for the Poseidon hash functionality
#[test]
fn test_poseidon_hash() -> Result<(), Error> {
    let msg = "This is a run-through of the Poseidon permutation function.";
    let hash = calculate_hash_fq(msg, "poseidon");
    assert_eq!(Ok(hash), Fq::from_str(&cast::hex_to_dec(
        "0x0b5de89054f5ff651f919eb397f4a125e9ba2aebd175dd809fe8fd02569d8087"
    )?));
    Ok(())
}
