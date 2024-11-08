/* Safecat template for a targeted Certificate Proof
 *
 * Generates a proof to verify the existence of a certificate for a public key, 
 * targeting a specific entity which is represented as a signed hash by the proof creator.
 *
 * Nargo Version: 0.37.0
 */
use dep::std;

HASHPATH_CODE_HERE

// Struct representing a person, with x and y coordinates for a public key
struct Person {
    x: Field,
    y: Field
}

// Struct representing a digital signature, with components s, rx, and ry
struct Signature {
    rx: Field,
    ry: Field,
    s: Field
}

// Struct representing a certificate
struct Certificate {
    cert_type: Field,
    person: Person,
    expiration: Field,
}

impl Certificate {
    // Method to hash the certificate data using the Poseidon hash function
    fn hash(self) -> Field {
        let certificate_as_array : [Field; 4] = [self.cert_type, self.person.x, self.person.y, self.expiration];
        std::hash::poseidon::bn254::hash_4(certificate_as_array)
    }
}

struct ToWhom {
    hash: Field,
    rx: Field,
    ry: Field,
    s: Field
}

/// Verifies the existence of a certificate for a given public key.
/// 
/// # Arguments
/// - `cert_type`: Type of certificate being verified.
/// - `babyjubjub_pubkey`: Public key of the person whose certificate is being verified.
/// - `society_root`: Root of the society Merkle tree.
/// - `last_checked_timestamp`: Timestamp to ensure the certificate's validity.
/// - `expiration`: Expiration date of the certificate.
/// - `signer`: Signer associated with the certificate.
/// - `signature`: Signature of the signer.
/// - `hash_path`: Merkle hash path for the signer.
/// * `to_whom`: Hash of the entity for which the certificate is issued.
/// * `to_whom_signature: The signed to_whom hash by the babyjubjub_pubkey
fn main(
    cert_type: Field,
    babyjubjub_pubkey: pub Person,
    society_root: pub Field,
    last_checked_timestamp: pub Field,
    expiration: Field,
    signer: Person,
    signature: Signature,
    hash_path: HashPath,
    to_whom: pub ToWhom,
) {
    // Verify that the current timestamp is before the certificate expiration date
    assert(last_checked_timestamp.lt(expiration));

    // Create a Certificate struct
    let certificate = Certificate {
        cert_type: cert_type,
        person: babyjubjub_pubkey,
        expiration: expiration
    };

    // Verify signature
    let verify_signature = dep::std::eddsa::eddsa_poseidon_verify(signer.x, signer.y, signature.s, signature.rx, signature.ry, certificate.hash());

    // Calculate the signer leaf value
    let leaf_signer : Field = std::hash::pedersen_hash([signer.x, signer.y]);

    // Calculate the Merkle root using second signer hash path
    let merkel_root = std::merkle::compute_merkle_root(leaf_signer, hash_path.index, hash_path.path);

    // Verify that the calculated Merkle roots match the society_root
    assert(merkel_root == society_root);

    // Verify signature on to_whom
    let verify_signature_on_to_whom = 
        dep::std::eddsa::eddsa_poseidon_verify(babyjubjub_pubkey.x, babyjubjub_pubkey.y, to_whom.s, to_whom.rx, to_whom.ry, to_whom.hash);    

    // Assert that the signatures are correct
    assert(verify_signature);
    assert(verify_signature_on_to_whom); 
}