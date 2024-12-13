use crate::{consts, Error};
use std::fs;
use std::io::Write;

// Saves a new Woolball name to file
pub fn set_name(folder_path: &str, wbname_filename: &str, name: &str) -> Result<(), Error> {
    // Save wbname key to file
    let wbname_path_filename = format!("{}/{}", folder_path, wbname_filename);

    // Create the directory if it doesn't exist
    fs::create_dir_all(folder_path)
        .map_err(|e| format!("Failed to create directory '{}': {}", folder_path, e))?;

    // Write the "name" to the "wbname_path_filename"
    fs::File::create(&wbname_path_filename)
        .and_then(|mut file| file.write_all(name.as_bytes()))
        .map_err(|e| format!("Failed to write to file '{}': {}", wbname_path_filename, e))?;

    // Print success message to terminal
    println!(
        "Saved the new Woolball Name in {}{}{} file",
        consts::GREEN_COLOR_ANSI,
        wbname_path_filename,
        consts::RESET_COLOR_ANSI
    );

    Ok(())
}
