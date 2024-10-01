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
    birthdate: Field
}

// Struct representing a hash path in a Merkle tree
struct HashPath {
    path: [Field; 2],
    index: Field
}

impl Certificate {
    // Method to hash the certificate data using the Poseidon hash function
    fn hash(self) -> Field {
        let certificate_as_array : [Field; 5] = [self.cert_type, self.person.x, self.person.y, self.birthdate, self.expiration];
        std::hash::poseidon::bn254::hash_5(certificate_as_array)
    }
}

// Function to check that a person has a type 1 certificates signed by one signers
// It takes the following arguments:
// - person: The person whose certificate is being verified (address)
// - trust_kernel_root: The root of the trust kernel Merkle tree
// - last_checked_timestamp: The timestamp in which we check that the certificate is still valid
// - expiration: The expiration date of the certificate
// - birthdate: The person's birthdate
// - signers: one person representing the signers
// - signatures: one signatures corresponding to the signer
// - signers_hash_path: One HashPath structs representing the hash path for the signer
fn main(
    cert_type: Field,
    person: pub Person,
    trust_kernel_root: pub Field,
    last_checked_timestamp: pub Field,
    expiration: Field,
    birthdate: Field,
    signers: [ Person; 1],
    signatures: [ Signature; 1],
    signers_hash_path: [HashPath; 1]
) {
    // Verify that the current timestamp is before the certificate expiration date
    assert(last_checked_timestamp.lt(expiration));

    // Create a Certificate struct with type 1 (birth certificate)
    let certificate = Certificate {
        cert_type: cert_type,
        person: person,
        birthdate: birthdate,
        expiration: expiration
    };

    // Verify signatures
    let verify_signature = dep::std::eddsa::eddsa_poseidon_verify(signers[0].x, signers[0].y, signatures[0].s, signatures[0].rx, signatures[0].ry, certificate.hash());

    // Calculate the Merkle root using the first signer hash path
    let leaf_signer : Field = std::hash::pedersen_hash([signers[0].x, signers[0].y]);

    // Calculate the Merkle root using the second signer hash path
    let merkel_root = std::merkle::compute_merkle_root(leaf_signer, signers_hash_path[0].index, signers_hash_path[0].path);

    // Verify that the calculated Merkle roots match the trust kernel root
    assert(merkel_root == trust_kernel_root);

    // Verify that both signatures are correct
    assert(verify_signature);
}