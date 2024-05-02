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
    person: Person,
    expiration: Field,
    cert_type: Field,
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
        let certificate_as_array : [Field; 5] = [self.person.x, self.person.y, self.expiration, self.cert_type, self.birthdate];
        std::hash::poseidon::bn254::hash_5(certificate_as_array)
    }
}

// Function to check that a person has a type 1 certificates signed by two signers
// It takes the following arguments:
// - person: The person whose certificate is being verified (address)
// - trust_kernel_root: The root of the trust kernel Merkle tree
// - last_checked_timestamp: The timestamp in which we check that the certificate is still valid
// - expiration: The expiration date of the certificate
// - birthdate: The person's birthdate
// - signers: An array of two persons representing the signers
// - signature: An array of two signatures corresponding to the signers
// - signers_hash_path: An array of two HashPath structs representing the hash paths for the signers
fn main(
    person: pub Person,
    trust_kernel_root: pub Field,
    last_checked_timestamp: pub Field,
    expiration: Field,
    birthdate: Field,
    signers: [ Person; 2],
    signature: [ Signature; 2],
    signers_hash_path: [HashPath; 2]
) {
    // Verify that the current timestamp is before the certificate expiration date
    assert(last_checked_timestamp.lt(expiration));

    // Create a Certificate struct with type 1 (birth certificate)
    let certificate = Certificate {
        person: person,
        expiration: expiration,
        cert_type: 1,
        birthdate: birthdate
    };

    // Verify signatures
    let verify_signature_1 = dep::std::eddsa::eddsa_poseidon_verify(signers[0].x, signers[0].y, signature[0].s, signature[0].rx, signature[0].ry, certificate.hash());
    let verify_signature_2 = dep::std::eddsa::eddsa_poseidon_verify(signers[1].x, signers[1].y, signature[1].s, signature[1].rx, signature[1].ry, certificate.hash());

    // Calculate the Merkle root using the first signer hash path
    let leaf_signer1 : Field = std::hash::pedersen_hash([signers[0].x, signers[0].y]);
    let leaf_signer2 : Field = std::hash::pedersen_hash([signers[1].x, signers[1].y]);

    // Calculate the Merkle root using the second signer hash path
    let merkel_root1 = std::merkle::compute_merkle_root(leaf_signer1, signers_hash_path[0].index, signers_hash_path[0].path);
    let merkel_root2 = std::merkle::compute_merkle_root(leaf_signer2, signers_hash_path[1].index, signers_hash_path[1].path);

    // Verify that the calculated Merkle roots match the trust kernel root
    assert(merkel_root1 == trust_kernel_root);
    assert(merkel_root2 == trust_kernel_root);

    // Verify that both signatures are correct
    assert(verify_signature_1);
    assert(verify_signature_2);
}