/* Safecat template for a certificates proof.
 *
 * Generates a proof to verify the existence of a certificate for a public key.
 * 
 * Nargo version = 0.37.0
 */
use dep::std;

// This will be replaced by "hash_path" structure by Safecat
HASHPATH_CODE_HERE

// Struct representing a person, with x and y coordinates for a public key
struct Person {
    x: Field,
    y: Field
}

// Struct representing a digital signature, with components s, rx, and ry
struct Signature {
    s: Field,
    rx: Field,
    ry: Field
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

// Function to check that a person has a type 1 certificates signed by one signers
// It takes the following arguments:
// - person: The person whose certificate is being verified (address)
// - trust_kernel_root: The root of the trust kernel Merkle tree
// - last_checked_timestamp: The timestamp in which we check that the certificate is still valid
// - expiration: The expiration date of the certificate
// - signers: one person representing the signers
// - signatures: one signatures corresponding to the signer
// - signers_hash_path: One HashPath structs representing the hash path for the signer
fn main(
    cert_type: Field,
    babyjubjub_pubkey: pub Person,
    society_root: pub Field,
    last_checked_timestamp: pub Field,
    expiration: Field,
    signer: Person,
    signature: Signature,
    hash_path: HashPath
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

    // Calculate the Merkle root using the signer hash path
    let merkel_root = std::merkle::compute_merkle_root(leaf_signer, hash_path.index, hash_path.path);

    // Verify that the calculated Merkle roots match the society_root
    assert(merkel_root == society_root);

    // Verify that the signatures is correct
    assert(verify_signature);
}