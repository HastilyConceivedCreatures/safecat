// An object enhancing signatures with info about the signer,
// and serilization functions
use crate::{
    crypto_structures::babyjubjub,
    io_utils,
    serialization::{ark_de, ark_se},
    Error,
    consts,
};
use ark_bn254::Fr as Fq;
use babyjubjub_ark::Fr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub s: Fr,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub rx: Fq,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub ry: Fq,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureAndSigner {
    pub signature: Signature,
    pub signer: babyjubjub::PubKey,
}

impl SignatureAndSigner {
    // Signs a hash. Returns a signature struct
    pub fn sign_hash(hash_bn254: Fq) -> Result<SignatureAndSigner, Error> {
        // Construct full path to the private key file
        let privkey_path_filename = consts::DATA_DIR.to_string() + "/" + consts::PRIVATE_KEY_FILENAME;

        // Check if private key file exists
        if !io_utils::file_exists("", &privkey_path_filename)? {
            return Err("No key has been generated yet.".into());
        }

        // Load private key from file
        let private_key = babyjubjub::PrivKey::read_from_file(&privkey_path_filename)?;

        // Sign the hash
        let signature: Signature = private_key.sign(hash_bn254)?;

        let signature_and_signer = SignatureAndSigner {
            signature: signature,
            signer: private_key.public(),
        };

        Ok(signature_and_signer)
    }
}
