/* casting data into BN256 scalar field */
use crate::{cast, consts, io_utils, Error};

// the scalar field of BN254 curve
pub use ark_bn254::Fr as BN254R;
use ark_std::str::FromStr;
use num::Num;
use num_bigint::BigUint;
use poseidon_ark::Poseidon;

// for date_to_bn254
use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};

// existing functions
// BN254R::from(x), where x is u128/u64/u32/u8/bool or i128/i64/i32/i8,
// BN254::from_str(s), where s is a string of decimal numbers as a (congruent) prime field element

pub fn hex_to_bn254_r(hex_string: &str) -> Result<BN254R, Error> {
    // Strip '0x' prefix if present
    let hex_str = if hex_string.starts_with("0x") || hex_string.starts_with("0X") {
        &hex_string[2..]
    } else {
        hex_string
    };

    // Convert hex string to BigUint
    let x_decimal = BigUint::from_str_radix(hex_str, 16)?;

    // Convert BigUint to Fq
    let x = BN254R::from(x_decimal);

    Ok(x)
}

pub fn woolball_name_to_bn254(name: &str) -> Result<BN254R, Error> {
    // calculate hash
    let mut parts = name.split('.').collect::<Vec<&str>>();

    // Initialize the hash with the rightmost part, which includes the '#'
    let mut current_hash = {
        let last_part = parts
            .pop()
            .expect("Input should contain at least one part ending with '#'");
        cast::hash256_as_string(last_part)
    };

    // Iterate from right to left, combining the current part with the hash of the previous step
    while let Some(part) = parts.pop() {
        let combined = format!("{}{}", part, current_hash);
        current_hash = cast::hash256_as_string(&combined);
    }

    // uint256 => BN254R
    let sha256_bn254r = message_to_bn254_vec(&current_hash)?;

    Ok(sha256_bn254r)
}

// Casts int256/uint256 to bn254R. Since bn254R has only 254 bits,
// we simply hash the int256/uint256 to do that. This keeps uniqueness,
// but doesn't allow to do arithmatics on the values. However, for any
// data item that needs arithmatics an integer with less bits should be used.
pub fn uint256_to_bn254(uint256_str: &str) -> Result<BN254R, Error> {
    let hex_str1 = uint256_str_to_hex_str(uint256_str)?;
    let hex_str = hex_str1.as_str();

    if hex_str.len() > 64 {
        return Err("Hex string length exceeds 64 characters")?;
    }
    if !hex_str.chars().all(|c| c.is_digit(16)) {
        return Err("Hex string contains invalid characters")?;
    }

    message_to_bn254_vec(hex_str)
}

pub fn uint256_str_to_hex_str(uint256_str: &str) -> Result<String, Error> {
    if uint256_str.starts_with("0x") {
        Ok(uint256_str[2..].to_string())
    } else {
        Ok(num_bigint::BigUint::from_str(uint256_str)?.to_str_radix(16))
    }
}

pub fn str_date_to_bn254(date: &str) -> Result<BN254R, Error> {
    // Try to parse the input as a date (YYYY-MM-DD)
    if let Ok(naive_date) = NaiveDate::parse_from_str(date, "%Y-%m-%d") {
        // Naive date time, with no time zone information
        let naive_datetime =
            NaiveDateTime::new(naive_date, NaiveTime::from_hms_opt(23, 59, 59).unwrap());
        let timestamp = naive_datetime.and_utc().timestamp();

        println!("datetime_utc: {}", timestamp);

        return Ok(BN254R::from(timestamp));
    }

    // Try to parse the input as a UNIX timestamp
    if let Ok(timestamp) = date.parse::<i64>() {
        return Ok(BN254R::from(timestamp));
    }

    // If both parsing attempts fail, return an error
    Err("Bad date format")?
}

pub fn datetime_utc_to_bn254(datetime: DateTime<Utc>) -> Result<BN254R, Error> {
    let datetime_i64 = datetime.timestamp();

    Ok(BN254R::from(datetime_i64))
}

// String message to bn256 vector
// It creates a Poseidon hash of the message
pub fn message_to_bn254_vec(message: &str) -> Result<BN254R, Error> {
    // calculate max message length for Poesidon hash
    const MAX_POSEIDON_MESSAGE_LEN: usize =
        consts::MAX_POSEIDON_PERMUTATION_LEN * consts::PACKED_BYTE_LEN;

    if message.len() > MAX_POSEIDON_MESSAGE_LEN {
        Err("Message is too long")?;
    }

    let bytes = message.as_bytes();

    // Pack the message bytes into right-aligned 31-byte chunks
    let fr_vector: Vec<BN254R> = cast::bytes_to_fields(bytes)
        .iter()
        .map(|&b| BN254R::from_str(&b.to_string()).unwrap())
        .collect();

    // Create a Poseidon hash function
    let poseidon = Poseidon::new();

    // // Hash the input vector
    Ok(poseidon.hash(fr_vector).unwrap())
}

pub fn babyjubjub_pubkey_to_bn254(pubkey: &str) -> Result<Vec<BN254R>, Error> {
    // Split the public key string into two parts: pubkey_x_str and pubkey_y_str
    let (pubkey_x_str, pubkey_y_str) = io_utils::split_hex_string(pubkey);

    // Convert the hex strings to BN254R
    let pubkey_x_bn254r = hex_to_bn254_r(&pubkey_x_str)?;
    let pubkey_y_bn254r = hex_to_bn254_r(&pubkey_y_str)?;

    // Return the result as a vector
    Ok(vec![pubkey_x_bn254r, pubkey_y_bn254r])
}

pub fn evm_address_to_bn254(hex_address: &str) -> Result<BN254R, Error> {
    let address_dec = cast::hex_to_dec(&hex_address).unwrap();
    let address_bn254 = BN254R::from_str(&*address_dec).unwrap();

    Ok(address_bn254)
}
