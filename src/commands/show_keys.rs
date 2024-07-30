use crate::{crypto_structures::babyjubjub, Error};

// Displays private and public keys based on the specified output format.
pub fn show_keys(folder_path: &str, privkey_filename: &str, output_format: &str) -> Result<(), Error> {
    // Construct full path to the private key file
    let privkey_path_filename = folder_path.to_string() + "/" + privkey_filename;

    // Load private key from the specified file
    let private_key = babyjubjub::PrivKey::read_from_file(privkey_path_filename.as_str())?;

    // Generate the corresponding public key
    let public_key = private_key.public();

    // Check the output format and display keys accordingly
    if output_format == "detailed" {
        // Print private key in detailed format
        println!("private key: {}", private_key.to_dec_str());

        // Print public key fields in detailed format
        println!(
            "public key Field X: {}",
            babyjubjub::fq_to_dec_str(&public_key.x)
        );
        println!(
            "public key Field Y: {}",
            babyjubjub::fq_to_dec_str(&public_key.y)
        );
    } else if output_format == "hex" {
        // Print private key in hex format
        println!("private key: {}", private_key.to_hex_str());

        // Print public key in hex format
        println!("public key: {}", public_key.to_hex_str());
    }

    Ok(())
}
