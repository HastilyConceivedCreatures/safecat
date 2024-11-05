/* Verify certificates for a public key example:
 * verifies that a person, reprenseted as public key, is human
 * has two certificates of type 1 (meaning, certificate of human for an public key)
 * Nargo version = 0.28.0
 */
use dep::std;

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

// Struct representing a hash path in a Merkle tree
struct HashPath {
    path: [Field; 2],
    index: Field
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
    BabyjubjubPubkey: pub Person,
    society_root: pub Field,
    LastCheckedTimestamp: pub Field,
    Expiration: Field,
    signer: Person,
    signature: Signature,
    hash_path: HashPath
) {
    // Verify that the current timestamp is before the certificate expiration date
    assert(LastCheckedTimestamp.lt(Expiration));

    // Create a Certificate struct with type 1 (birth certificate)
    let certificate = Certificate {
        cert_type: cert_type,
        person: BabyjubjubPubkey,
        expiration: Expiration
    };

    // Verify signatures
    let verify_signature = dep::std::eddsa::eddsa_poseidon_verify(signer.x, signer.y, signature.s, signature.rx, signature.ry, certificate.hash());

    // Calculate the Merkle root using the first signer hash path
    let leaf_signer : Field = std::hash::pedersen_hash([signer.x, signer.y]);

    // Calculate the Merkle root using the second signer hash path
    let merkel_root = std::merkle::compute_merkle_root(leaf_signer, hash_path.index, hash_path.path);

    // Verify that the calculated Merkle roots match the trust kernel root
    assert(merkel_root == society_root);

    // Verify that both signatures are correct
    assert(verify_signature);
}