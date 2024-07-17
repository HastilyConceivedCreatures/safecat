// An object enhancing signatures with info about the signer,
// and serilization functions
use crate::{
    crypto_structures::babyjubjub,
    io_utils,
    serialization::{ark_de, ark_se},
    Error,
};
use ark_bn254::Fr as BN254R;
use babyjubjub_ark::{Fr, Signature as SignatureComponent};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub s: Fr,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub rx: BN254R,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub ry: BN254R,
    pub signer: babyjubjub::Pubkey,
}

impl Signature {
    // Signs a hash. Returns a signature struct
    pub fn sign_hash(hash_bn254: BN254R) -> Result<Signature, Error> {
        // Check if private key file exists
        if !io_utils::file_exists("", "priv.key")? {
            return Err("No key has been generated yet.".into());
        }

        // Load private key from file
        let private_key = io_utils::load_private_key("priv.key")?;

        // Sign the hash
        let signature_components: SignatureComponent = private_key
            .sign(hash_bn254)
            .map_err(|e| format!("Failed to sign message: {}", e))?;

        let signature = Signature {
            s: signature_components.s,
            rx: signature_components.r_b8.x,
            ry: signature_components.r_b8.y,
            signer: babyjubjub::Pubkey::from_point(private_key.public()),
        };

        Ok(signature)
    }
}
