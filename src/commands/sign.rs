use crate::crypto_structures::{babyjubjub, signature};
use crate::{cast, consts, io_utils, Error};
use ark_std::str::FromStr;
use babyjubjub_ark::{verify, Fq};
use poseidon_ark::Poseidon; // import to use from_str in structs

// Signs a message using BabyJubJub based on the specified hash algorithm and output format.
pub fn sign_and_print_message(
    message_to_sign_string: String,
    output_format: String,
) -> Result<(), Error> {
    // Sign the message
    let (signature, hash_fq) = sign_message(message_to_sign_string)?;

    // Print the hash
    println!("message Hash: {}", babyjubjub::fq_to_dec_str(&hash_fq));

    if output_format == "detailed" {
        // Print signature
        println!(
            "Signature: R.X: {}",
            babyjubjub::fq_to_dec_str(&signature.rx)
        );
        println!(
            "Signature: R.Y: {}",
            babyjubjub::fq_to_dec_str(&signature.ry)
        );
        println!(
            "Signature: S: {}",
            babyjubjub::fr_to_dec_string(&signature.s)
        );
    } else if output_format == "hex" {
        // change signature variables to hex
        let signature_x_hex = babyjubjub::fq_to_hex_str(&signature.rx);
        let signature_y_hex = babyjubjub::fq_to_hex_str(&signature.ry);
        let signature_s_hex = babyjubjub::fr_to_hex_string(&signature.s);

        println!(
            "Signature: {}{}{}",
            signature_x_hex, signature_y_hex, signature_s_hex
        );
    }

    Ok(())
}

// Signs a message using BabyJubJub based on the specified output format *without* hashing it.
// This function assumes the message is already a hash
pub fn sign_and_print_babyjubjub_fq(
    hash_to_sign_string: String,
    output_format: String,
) -> Result<(), Error> {
    // Sign the message
    let (signature, hash_fq) = sign_babyjubjub_fq(hash_to_sign_string)?;

    // Print the hash
    println!("message Hash: {}", babyjubjub::fq_to_dec_str(&hash_fq));

    if output_format == "detailed" {
        // Print signature
        println!(
            "Signature: R.X: {}",
            babyjubjub::fq_to_dec_str(&signature.rx)
        );
        println!(
            "Signature: R.Y: {}",
            babyjubjub::fq_to_dec_str(&signature.ry)
        );
        println!(
            "Signature: S: {}",
            babyjubjub::fr_to_dec_string(&signature.s)
        );
    } else if output_format == "hex" {
        // change signature variables to hex
        let signature_x_hex = babyjubjub::fq_to_hex_str(&signature.rx);
        let signature_y_hex = babyjubjub::fq_to_hex_str(&signature.ry);
        let signature_s_hex = babyjubjub::fr_to_hex_string(&signature.s);

        println!(
            "Signature: {}{}{}",
            signature_x_hex, signature_y_hex, signature_s_hex
        );
    }

    Ok(())
}

// Hashes a message and then signs it. Returns the signature and the hash.
pub fn sign_message(message_to_sign_string: String) -> Result<(signature::Signature, Fq), Error> {
    // calculate max message length for Poseidon hash
    const MAX_POSEIDON_MESSAGE_LEN: usize =
        consts::MAX_POSEIDON_PERMUTATION_LEN * consts::PACKED_BYTE_LEN;

    if message_to_sign_string.len() > MAX_POSEIDON_MESSAGE_LEN {
        println!(
            "Message too long! Maximum message length with Poseidon  is {} characters",
            MAX_POSEIDON_MESSAGE_LEN
        );
    }

    let hash_fq = poseidon_message(&message_to_sign_string);

    // Check if private key file exists
    if !io_utils::file_exists(consts::DATA_DIR, consts::PRIVATE_KEY_FILENAME)? {
        return Err("No key has been generated yet.".into());
    }

    let privkey_path_filename = consts::DATA_DIR.to_string() + "/" + consts::PRIVATE_KEY_FILENAME;

    let private_key = babyjubjub::PrivKey::read_from_file(&privkey_path_filename)?;

    // Sign the message
    let signature: signature::Signature = private_key.sign(hash_fq)?;

    Ok((signature, hash_fq))
}

// Hashes a message and then signs it. Returns the signature and the hash.
fn sign_babyjubjub_fq(fq_as_str: String) -> Result<(signature::Signature, Fq), Error> {
    let hash_fq = Fq::from_str(&*fq_as_str).unwrap();

    // Check if private key file exists
    if !io_utils::file_exists(consts::DATA_DIR, consts::PRIVATE_KEY_FILENAME)? {
        return Err("No key has been generated yet.".into());
    }

    let privkey_path_filename = consts::DATA_DIR.to_string() + "/" + consts::PRIVATE_KEY_FILENAME;

    let private_key = babyjubjub::PrivKey::read_from_file(&privkey_path_filename)?;

    // Sign the message
    let signature: signature::Signature = private_key.sign(hash_fq)?;

    Ok((signature, hash_fq))
}

// Verifies a message signature using BabyJubJub based on the specified hash algorithm.
pub fn verify_signature(
    message_to_verify_string: String,
    signature_string: String,
    public_key_hex_string: String,
) -> Result<(), Error> {
    println!("message_to_verify_string: {}", message_to_verify_string);
    println!("public_key_hex_string: {}", public_key_hex_string);
    println!("signature_string: {}", signature_string);

    // calculate max message length for Poesidon hash
    const MAX_POSEIDON_MESSAGE_LEN: usize =
        consts::MAX_POSEIDON_PERMUTATION_LEN * consts::PACKED_BYTE_LEN;

    if message_to_verify_string.len() > MAX_POSEIDON_MESSAGE_LEN {
        println!(
            "Message too long! Maximum message length with Poseidon  is {} characters",
            MAX_POSEIDON_MESSAGE_LEN
        );
        std::process::exit(1);
    }

    let hash_fq = poseidon_message(&message_to_verify_string);

    // Create PublicKey and signature objects
    let public_key = cast::public_key_from_str(&public_key_hex_string)?;
    let signature = cast::signature_from_str(&signature_string)?;

    let correct = verify(public_key, signature, hash_fq);

    println!("signature is {}", correct);

    Ok(())
}

// Packs a message into an array and calculates its Poseidon hash
fn poseidon_message(message_to_verify_string: &str) -> Fq {
    let bytes = message_to_verify_string.as_bytes();

    // Pack the message bytes into right-aligned 31-byte chunks
    let fr_vector: Vec<Fq> = cast::bytes_to_fields(bytes)
        .iter()
        .map(|&b| Fq::from_str(&b.to_string()).unwrap())
        .collect();

    // Create a Poseidon hash function
    let poseidon_instance = Poseidon::new();

    // // Hash the input vector
    poseidon_instance.hash(fr_vector).unwrap()
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
    let hash = poseidon_message(msg);
    assert_eq!(
        Ok(hash),
        Fq::from_str(&cast::hex_to_dec(
            "0x0b5de89054f5ff651f919eb397f4a125e9ba2aebd175dd809fe8fd02569d8087"
        )?)
    );
    Ok(())
}
