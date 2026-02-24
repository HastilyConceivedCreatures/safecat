use crate::{consts, crypto_structures::babyjubjub, io_utils, Error};
use inquire::Select;
use reqwest::blocking::Client;
use serde_json::json;
use std::time::{Duration, Instant};

pub fn share_zed() -> Result<(), Error> {
    // 1. Load your own BabyJubJub public key (hex string, 128 chars)
    let pubkey_hex = load_own_zed_pubkey_hex()?;

    const SERVER: &str = "http://zed-test.almonit.club";

    let client = Client::new();

    // 2. Request one-time code from server
    let res = client
        .post(format!("{}/request-code", SERVER))
        .json(&json!({ "publicKey": pubkey_hex }))
        .send()
        .map_err(|e| format!("Failed to contact server: {}", e))?;

    if !res.status().is_success() {
        return Err(format!("Server error: {}", res.status()).into());
    }

    let json: serde_json::Value = res
        .json()
        .map_err(|_| "Invalid JSON from server".to_string())?;

    let code = json["code"]
        .as_str()
        .ok_or("No 'code' field in response")?
        .to_string();

    // 3. Show instructions to user
    println!("\nYour one-time code: \x1b[1m{}\x1b[0m", code);
    println!("Share this 6-digit code privately with the other person.\n");

    println!("Waiting for other side to confirm code...");

    let start = Instant::now();
    let timeout = Duration::from_secs(600); // 10 min

    let bob_name = loop {
        if start.elapsed() > timeout {
            return Err("Timeout waiting for approval".into());
        }

        std::thread::sleep(Duration::from_secs(4));

        let res = client
            .get(format!("{}/check-approval", SERVER))
            .query(&[("publicKey", &pubkey_hex)])
            .send()
            .map_err(|e| format!("Poll failed: {}", e))?;

        if res.status().is_success() {
            let json: serde_json::Value = res.json().unwrap_or_default();

            if json["pending"].as_bool().unwrap_or(false) {
                if let Some(name) = json["bobName"].as_str() {
                    break name.to_string();
                }
            }
        }
    };

    // Confirmation prompt
    let options = vec!["Yes", "No"];
    let answer = Select::new(
        &format!("Allow {} to receive your Zed public key?", bob_name),
        options,
    )
    .with_help_message("Select Yes/No and press Enter")
    .prompt()
    .map_err(|e| format!("Prompt failed: {}", e))?;

    let approve = answer == "Yes";

    // Send approval decision
    let res = client
        .post(format!("{}/approve", SERVER))
        .json(&json!({
            "publicKey": pubkey_hex,
            "approve": approve
        }))
        .send()
        .map_err(|e| format!("Failed to send approval: {}", e))?;

    if !res.status().is_success() {
        return Err(format!("Approval send failed: {}", res.status()).into());
    }

    if approve {
        println!("Public key shared successfully.");
    } else {
        println!("Request rejected.");
    }

    Ok(())
}

// Helper: load your own Zed/BabyJubJub pubkey as hex string
// Adjust path & logic to match how you actually store keys
fn load_own_zed_pubkey_hex() -> Result<String, Error> {
    // Construct full path to the private key file from constants
    let folder_path = consts::OUTPUT_DIR;
    let privkey_filename = consts::PRIVATE_KEY_FILENAME;
    let privkey_path_filename = folder_path.to_string() + "/" + privkey_filename;

    // Load private key from the specified file
    let private_key = babyjubjub::PrivKey::read_from_file(privkey_path_filename.as_str())?;

    // Generate the corresponding public key
    let public_key = private_key.public();

    let hex = public_key.to_hex_str();

    Ok(hex)
}
