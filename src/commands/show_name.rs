use crate::{consts, Error};
use std::fs;
use std::io::Read;

// Displays private and public keys based on the specified output format.
pub fn show_name(folder_path: &str, name_filename: &str) -> Result<(), Error> {
    // Construct full path to the name file
    let name_path_filename = format!("{}/{}", folder_path, name_filename);

    // Read the name from the file
    let mut file = fs::File::open(&name_path_filename)
        .map_err(|e| format!("Failed to open file '{}': {}", name_path_filename, e))?;
    let mut name = String::new();
    file.read_to_string(&mut name)
        .map_err(|e| format!("Failed to read file '{}': {}", name_path_filename, e))?;

    // Print the name in a detailed format with color
    println!(
        "Name: {}{}{}",
        consts::ORANGE_COLOR_ANSI,
        name,
        consts::RESET_COLOR_ANSI
    );

    Ok(())
}
