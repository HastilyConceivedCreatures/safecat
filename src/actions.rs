use crate::{
    cast, consts,
    crypto_structures::{babyjubjub, signature},
    io_utils, Error,
};

use ark_std::str::FromStr;
use babyjubjub_ark::{verify, Fq};
use poseidon_ark::Poseidon;

// Signs a message using BabyJubJub based on the specified hash algorithm and output format.
pub fn sign(message_to_sign_string: String, hash_algorithm: String, output_format: String) {
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
        println!("Signature: R.X: {}", cast::fq_to_dec_string(&signature.rx));
        println!("Signature: R.Y: {}", cast::fq_to_dec_string(&signature.ry));
        println!("Signature: S: {}", cast::fr_to_dec_string(&signature.s));
    } else if output_format == "hex" {
        // change signature variables to hex
        let signature_x_hex = cast::fq_to_hex_string(&signature.rx);
        let signature_y_hex = cast::fq_to_hex_string(&signature.ry);
        let signature_s_hex = cast::fr_to_hex_string(&signature.s);

        println!(
            "Signature: {}{}{}",
            signature_x_hex, signature_y_hex, signature_s_hex
        );
    }
}

// Signs a message using BabyJubJub based on the specified output format *without* hashing it.
// This function assumes the message is already a hash
pub fn sign_poseidon_hash(hash_to_sign_string: String, output_format: String) {
    // Sign the message
    let (signature, hash_fq) = match sign_poseidon_fq(hash_to_sign_string) {
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
        println!("Signature: R.X: {}", cast::fq_to_dec_string(&signature.rx));
        println!("Signature: R.Y: {}", cast::fq_to_dec_string(&signature.ry));
        println!("Signature: S: {}", cast::fr_to_dec_string(&signature.s));
    } else if output_format == "hex" {
        // change signature variables to hex
        let signature_x_hex = cast::fq_to_hex_string(&signature.rx);
        let signature_y_hex = cast::fq_to_hex_string(&signature.ry);
        let signature_s_hex = cast::fr_to_hex_string(&signature.s);

        println!(
            "Signature: {}{}{}",
            signature_x_hex, signature_y_hex, signature_s_hex
        );
    }
}

// Verifies a message signature using BabyJubJub based on the specified hash algorithm.
pub fn verify_signature(
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

// Calculate hash_fq based on hash_algorithm
fn calculate_hash_fq(message_to_verify_string: &str, hash_algorithm: &str) -> Fq {
    let mut hash_fq = Fq::from_str("0").unwrap();

    if hash_algorithm == "poseidon" {
        let bytes = message_to_verify_string.as_bytes();

        // Pack the message bytes into right-aligned 31-byte chunks
        let fr_vector: Vec<Fq> = cast::bytes_to_fields(bytes)
            .iter()
            .map(|&b| Fq::from_str(&b.to_string()).unwrap())
            .collect();

        // Create a Poseidon hash function
        let poseidon = Poseidon::new();

        // // Hash the input vector
        hash_fq = poseidon.hash(fr_vector).unwrap();
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
) -> Result<(signature::Signature, Fq), Error> {
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

    let private_key = babyjubjub::PrivKey::read_from_file("priv.key")?;

    // Sign the message
    let signature: signature::Signature = private_key.sign(hash_fq)?;

    Ok((signature, hash_fq))
}

// Hashes a message and then signs it. Returns the signature and the hash.
fn sign_poseidon_fq(fq_as_str: String) -> Result<(signature::Signature, Fq), Error> {
    let hash_fq = Fq::from_str(&*fq_as_str).unwrap();

    // Check if private key file exists
    if !io_utils::file_exists("", "priv.key")? {
        return Err("No key has been generated yet.".into());
    }

    let private_key = babyjubjub::PrivKey::read_from_file("priv.key")?;

    // Sign the message
    let signature: signature::Signature = private_key.sign(hash_fq)?;

    Ok((signature, hash_fq))
}

/// Test for the byte packing functionality
#[test]
fn byte_packing_test() -> Result<(), Error> {
    // Test case 1: Single field from 3 bytes
    let bytes: &[u8] = &[0x01, 0x02, 0x03];
    let fields = cast::bytes_to_fields(bytes);
    assert_eq!(fields.len(), 1);
    assert_eq!(
        fields[0],
        Fq::from_str(&cast::hex_to_dec("0x010203").unwrap()).unwrap()
    );

    // Test case 2: Multiple fields from 64 bytes
    let bytes: Vec<u8> = (0..64).collect();
    let fields = cast::bytes_to_fields(&bytes);
    assert_eq!(fields.len(), 3);
    assert_eq!(Ok(fields[0]), Fq::from_str(&cast::hex_to_dec("0x0001")?));
    assert_eq!(
        Ok(fields[1]),
        Fq::from_str(&cast::hex_to_dec(
            "0x02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        )?)
    );
    assert_eq!(
        Ok(fields[2]),
        Fq::from_str(&cast::hex_to_dec(
            "0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        )?)
    );
    Ok(())
}

/// Test for the Poseidon hash functionality
#[test]
fn test_poseidon_hash() -> Result<(), Error> {
    let msg = "This is a run-through of the Poseidon permutation function.";
    let hash = calculate_hash_fq(msg, "poseidon");
    assert_eq!(
        Ok(hash),
        Fq::from_str(&cast::hex_to_dec(
            "0x0b5de89054f5ff651f919eb397f4a125e9ba2aebd175dd809fe8fd02569d8087"
        )?)
    );
    Ok(())
}
