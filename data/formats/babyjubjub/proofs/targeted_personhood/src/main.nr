/* Verify certificates for a public key example:
 * verifies that a person, reprenseted as public key, is human
 * has two certificates of type 1 (meaning, certificate of human for an public key)
 * The proof is created for a specific requester, see details in code comments
 * Nargo version = 0.32.0
 */
use dep::std;

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
    birthdate: Field
}

struct ToWhomObject {
    hash: Field,
    rx: Field,
    ry: Field,
    s: Field
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

/// Validates that a person holds a type 1 certificate signed by an authorized signer.
/// 
/// # Arguments
/// 
/// * `cert_type` - The type of certificate being checked (Field).
/// * `person` - The person whose certificate is being verified (address).
/// * `society` - The root of the society Merkle tree. The leaves are public keys 
///               of trusted entities authorized to issue certificates.
/// * `last_checked_timestamp` - The timestamp when the certificate validity is checked.
/// * `expiration` - The expiration date of the certificate (Field).
/// * `birthdate` - The person's birthdate (Field).
/// * `signers` - An array containing one person representing the signers.
/// * `signatures` - An array containing one signature corresponding to the signer.
/// * `signers_hash_path` - An array containing one `HashPath` struct, representing 
///                         the hash path for the signer.
/// * `to_whom` - The entity or person to whom the certificate is issued (Field).
/// * `to_whom_signature` - The signature from the recipient entity or person.
fn main(
    cert_type: Field,
    BabyjubjubPubkey: pub Person,
    society: pub Field,
    lastCheckedTimestamp: pub Field,
    expiration: Field,
    signer: [ Person; 1],
    signature: [ Signature; 1],
    hash_path: [HashPath; 1],
    toWhom: pub ToWhomObject,
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

    print(to_whom_signature);

    // Verify signatures
    let verify_signature = dep::std::eddsa::eddsa_poseidon_verify(signers[0].x, signers[0].y, signatures[0].s, signatures[0].rx, signatures[0].ry, certificate.hash());

    // Calculate the Merkle root using the first signer hash path
    let leaf_signer : Field = std::hash::pedersen_hash([signers[0].x, signers[0].y]);

    // Calculate the Merkle root using the second signer hash path
    let merkel_root = std::merkle::compute_merkle_root(leaf_signer, signers_hash_path[0].index, signers_hash_path[0].path);

    // Verify that the calculated Merkle roots match the trust kernel root
    assert(merkel_root == society);

    // Verify signature on to_whom
    let verify_signature_on_to_whom = dep::std::eddsa::eddsa_poseidon_verify(person.x, person.y, to_whom_signature.s, to_whom_signature.rx, to_whom_signature.ry, to_whom);    

    // Verify that both signatures are correct
    assert(verify_signature);

    // Verify that the proof is signed for to_whom
    assert(verify_signature_on_to_whom); 
}