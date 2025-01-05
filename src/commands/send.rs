use crate::crypto_structures::babyjubjub::{self, Fq};
use crate::{
    commands::{show_name, sign},
    consts, io_utils, Error,
};
use chrono::Utc;
use reqwest::Client;
use serde_json::json; // Adjust field type if using a different one

pub async fn send(target_name: String, index: i32) -> Result<(), Error> {
    // Retrieve the certificate
    let certificate = io_utils::get_certificate(index)?;

    // Query parameters
    let requester_name = show_name::get_name(consts::OUTPUT_DIR, consts::WBNAME_FILENAME)?;

    // Encode parameters to handle special characters like `#`
    let encoded_requester_name = urlencoding::encode(&requester_name);
    let encoded_target_name = urlencoding::encode(&target_name);

    // Generate timestamp and its representation
    let timestamp = Utc::now().timestamp();
    let timestamp_as_fq_then_str_hex = babyjubjub::fq_to_dec_str(&Fq::from(timestamp));

    // Sign the timestamp
    let (request_signature, _) = sign::sign_babyjubjub_fq(timestamp_as_fq_then_str_hex)?;
    let request_signature_json = request_signature.to_json()?;

    // Prepare the JSON payload
    let payload = json!({
        "requesterName": encoded_requester_name,
        "requestSignature": request_signature_json,
        "timestamp": timestamp,
        "targetName": encoded_target_name,
        "certificate": certificate,
    });

    // Send the request to the server
    let client = Client::new();
    let server_url = format!("{}/save-certificate", consts::WB_SERVER_URL);

    let response = client
        .post(&server_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    // Handle the response
    if response.status().is_success() {
        println!("Certificate sent successfully!");
        Ok(())
    } else {
        let error_message = response.text().await?;
        eprintln!("Failed to send certificate: {}", error_message);
        Err(Box::from("Failed to send certificate"))
    }
}
