// An object enhancing signatures with info about the signer,
// and serilization functions
use crate::{
    consts,
    crypto_structures::babyjubjub,
    io_utils,
    serialization::{ark_de, ark_se},
    Error,
};
use ark_bn254::Fr as Fq;
use ark_std::str::FromStr;
use babyjubjub_ark::Fr;
use serde::{Deserialize, Serialize};
use serde_json::json; // For constructing JSON objects

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub s: Fr,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub rx: Fq,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub ry: Fq,
}

impl Signature {
    // To represent a signature as a vector of Base fields (Fq),
    // we treat the Scalar Field element (Fr, signature.s) as Fq.
    pub fn to_fq_vec(&self) -> Vec<Fq> {
        let s_str_dec = &self.s.to_string();

        vec![Fq::from_str(s_str_dec).unwrap(), self.rx, self.ry]
    }

    /// Converts the `Signature` instance to a JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        // Use fq_to_dec_str for Fq fields and .to_string() for Fr field
        let s_str = self.s.to_string();
        let rx_str = babyjubjub::fq_to_dec_str(&self.rx);
        let ry_str = babyjubjub::fq_to_dec_str(&self.ry);

        // Create JSON structure
        let json_obj = json!({
            "s": s_str,
            "rx": rx_str,
            "ry": ry_str,
        });

        // Convert JSON structure to a String
        serde_json::to_string(&json_obj)
    }
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
        let privkey_path_filename =
            consts::OUTPUT_DIR.to_string() + "/" + consts::PRIVATE_KEY_FILENAME;

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
