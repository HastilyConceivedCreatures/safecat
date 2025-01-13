use crate::crypto_structures::{
    babyjubjub::{self, Fq},
    certificate::Cert,
    signature::SignatureAndSigner,
};
use crate::{
    commands::{show_name, sign},
    consts, io_utils, Error,
};
use chrono::Utc;
use reqwest::Client;
use serde_json::{self, Value}; // Adjust field type if using a different one

pub async fn receive() -> Result<(), Error> {
    // target_name in the query parameters is actually the Safecat user name
    let target_name = show_name::get_name(consts::OUTPUT_DIR, consts::WBNAME_FILENAME)?;

    // Encode parameters to handle special characters like `#`
    let encoded_target_name = urlencoding::encode(&target_name);

    // Generate timestamp and its representation
    let timestamp = Utc::now().timestamp();
    let timestamp_as_fq_then_str_hex = babyjubjub::fq_to_dec_str(&Fq::from(timestamp));

    // Sign the timestamp
    let (request_signature, _) = sign::sign_babyjubjub_fq(timestamp_as_fq_then_str_hex)?;
    let request_signature_json = request_signature.to_json()?;

    let server_url = format!(
        "{}/get-certificates/{}?timestamp={}&requestSignature={}",
        consts::WB_SERVER_URL,
        encoded_target_name,
        timestamp,
        request_signature_json
    );

    // Send the request to the server
    let client = Client::new();
    let response = client
        .get(&server_url)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    // Handle the response
    if response.status().is_success() {
        let certificates = response.text().await?;
        process_certificates_response(&certificates)?;
        Ok(())
    } else {
        let error_message = response.text().await?;
        eprintln!("Failed to receive certificates. Error: {}", error_message);
        Err(Box::from("Failed to receive certificates"))
    }
}

pub fn process_certificates_response(response_text: &str) -> Result<(), Error> {
    // Parse the response text into a JSON value
    let response: Value = serde_json::from_str(response_text)?;

    // Extract the certificates array from the response
    let certificates = response["certificates"]
        .as_array()
        .ok_or("Certificates field is not an array")?;

    // Process each certificate
    for cert_entry in certificates {
        // Extract the certificate string
        let certificate_str = cert_entry["certificate"]
            .as_str()
            .ok_or("Certificate field is not a string")?;

        // Split the certificate into parts
        let parts: Vec<&str> = certificate_str.splitn(2, '\n').collect();
        if parts.len() != 2 {
            return Err("Invalid certificate format".into());
        }

        // Deserialize Cert and SignatureAndSigner structs
        let cert: Cert =
            serde_json::from_str(parts[0]).map_err(|e| format!("Failed to parse Cert: {}", e))?;
        let signature: SignatureAndSigner = serde_json::from_str(parts[1])
            .map_err(|e| format!("Failed to parse SignatureAndSigner: {}", e))?;

        // Call the save_certificate function
        io_utils::save_certificate(cert, signature, consts::RECEIVED_CERT_FOLDER)?;
    }

    println!("All certificates processed successfully.");
    Ok(())
}
