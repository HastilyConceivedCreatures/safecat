use crate::crypto_structures::babyjubjub::{self, Fq, PubKey};
use crate::{
    commands::{show_name, sign},
    consts, Error,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use urlencoding;

use super::babyjubjub::fq_to_dec_str;

#[derive(Debug, Serialize, Deserialize)]
pub struct WoolballName {
    pub name: String,
}

impl WoolballName {
    pub fn id(&self) -> Fq {
        babyjubjub::woolball_name_to_fq(&self.name).unwrap()
    }

    pub fn to_fq_vec(&self) -> Vec<Fq> {
        vec![self.id()]
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PublicKeyResponse {
    #[serde(rename = "pubKeyX")]
    pub_key_x: String,
    #[serde(rename = "pubKeyY")]
    pub_key_y: String,
}

pub async fn fetch_publickey_for_wbname(target_name: String) -> Result<PubKey, Error> {
    // Query parameters
    let requester_name = show_name::get_name(consts::OUTPUT_DIR, consts::WBNAME_FILENAME)?;

    // Encode parameters to handle special characters like `#`
    let encoded_requester_name = urlencoding::encode(&requester_name);
    let encoded_target_name = urlencoding::encode(&target_name);

    let timestamp = Utc::now().timestamp();
    let timestamp_as_fq_then_str_hex = fq_to_dec_str(&Fq::from(timestamp));

    // Represent signature as JSON
    let (request_signature, _) = sign::sign_babyjubjub_fq(timestamp_as_fq_then_str_hex)?;
    let request_signature_json = request_signature.to_json()?;

    let server_fetch_name_url = format!(
        "{}/public-key/{}",
        consts::WB_SERVER_URL,
        encoded_target_name
    );

    // Construct the full URL with query parameters
    let url = format!(
        "{}?requesterName={}&timestamp={}&requestSignature={}",
        server_fetch_name_url, encoded_requester_name, timestamp, request_signature_json
    );

    // Make the GET request
    let response = reqwest::get(&url)
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    // Check the response status
    if response.status().is_success() {
        // Parse the JSON response
        let public_key: PublicKeyResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse JSON: {}", e))?;

        // Check if `pub_key_x` or `pub_key_y` represent zero
        let is_x_zero = public_key.pub_key_x
            == "0x0000000000000000000000000000000000000000000000000000000000000000";
        let is_y_zero = public_key.pub_key_y
            == "0x0000000000000000000000000000000000000000000000000000000000000000";

        if is_x_zero || is_y_zero {
            return Err(format!(
                "{}Error: The name '{}' is unregistered or one of its public keys is empty (zero).{}",
                consts::RED_COLOR_ANSI,
                target_name,
                consts::RESET_COLOR_ANSI
            )
            .into());
        }

        // Create a PubKey using `babyjubjub::hex_to_fq`
        let x = babyjubjub::hex_to_fq(&public_key.pub_key_x)
            .map_err(|e| format!("Failed to convert pubKeyX to Fq: {}", e))?;
        let y = babyjubjub::hex_to_fq(&public_key.pub_key_y)
            .map_err(|e| format!("Failed to convert pubKeyY to Fq: {}", e))?;

        // Return the constructed PubKey
        Ok(PubKey { x, y })
    } else {
        // Print error if the request fails
        let error_message = response
            .text()
            .await
            .map_err(|e| format!("Failed to read error message: {}", e))?;
        eprintln!("Error: {}", error_message);

        Err(format!("Server returned error: {}", error_message).into())
    }
}
