use crate::{
    consts,
    crypto_structures::{certificate, signature::SignatureAndSigner},
    io_utils, Error,
};

use std::fs::OpenOptions;
use std::io::Read;
use toml;

pub fn attest(format: String) -> Result<(), Error> {
    println!("format: {}", format);

    // calculating certificate formats file
    let formats_folder_path = consts::DATA_DIR.to_string() + "/" + consts::CERTIFICATE_FORMATS;

    // Construct the file path based on the `format` parameter
    let file_path = format!("{}/{}/format.toml", formats_folder_path, format);

    // Read the certificate format from the TOML file
    let cert_format = read_cert_format_from_toml(&file_path)?;

    // create certificate
    let cert: certificate::Cert = certificate::insert_cert_data(cert_format, &format);
    let cert_hash = cert.poseidon_hash();

    // sign certificate
    let signature_and_signer = SignatureAndSigner::sign_hash(cert_hash).unwrap();

    // save certificate to disk
    let filename = io_utils::save_certificate(cert, signature_and_signer);

    println!("The certificate was saved to file: {}", filename?);

    Ok(())
}

fn read_cert_format_from_toml(file_name: &str) -> Result<certificate::CertFormat, Error> {
    let mut file = OpenOptions::new().read(true).open(file_name)?;

    let mut toml_string = String::new();
    file.read_to_string(&mut toml_string)?;

    let cert_format: certificate::CertFormat = toml::from_str(&toml_string)?;
    Ok(cert_format)
}
