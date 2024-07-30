use crate::{crypto_structures::babyjubjub, Error, consts};

// Generates a new private key and saves it to file
pub fn generate(folder_path: &str, privkey_filename: &str) -> Result<(), Error> {
    // Generate a new private key
    let private_key = babyjubjub::PrivKey::generate();

    // Save private key to file
    let privkey_path_filename = folder_path.to_string() + "/" + privkey_filename;
    private_key.save_to_file(privkey_path_filename.as_str())?;

    // Print success message to terminal
    println!(
        "Saved the new private key in {}{}{} file",
        consts::GREEN_COLOR_ANSI,
        privkey_path_filename,
        consts::RESET_COLOR_ANSI
    );

    Ok(())
}
