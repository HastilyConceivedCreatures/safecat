use crate::{
    certificate_formats,
    crypto_structures::{certificate, signature::SignatureAndSigner},
    io_utils, Error,
};

pub fn attest(format: String) -> Result<(), Error> {
    let cert_format: certificate::CertFormat;
    if format == "babyjubjub" {
        cert_format = certificate_formats::cert_format_pubkeybabyjubjub();
    } else if format == "babyjubjub-evmaddres" {
        cert_format = certificate_formats::cert_format_evm_address();
    } else {
        //"babyjubjub-woolball"
        cert_format = certificate_formats::cert_format_woolball_pubkeybabyjubjub();
    }

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
