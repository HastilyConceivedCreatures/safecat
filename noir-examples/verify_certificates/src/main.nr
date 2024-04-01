mod data_processing;

use dep::std;
use data_processing::bytes_to_fields;

struct Person {
    x: Field,
    y: Field
}

struct Signature {
    s: Field,
    rx: Field,
    ry: Field
}

struct Certificate {
    person: Person,
    expiration: Field,
    cert_type: Field,
    birthdate: Field
}

struct HashPath {
    path: [Field; 2],
    index: Field
}

impl Certificate {
    fn hash(self) -> Field {
        let certificate_as_array : [Field; 5] = [self.person.x, self.person.y, self.expiration, self.cert_type, self.birthdate];
        std::hash::poseidon::bn254::hash_5(certificate_as_array)
    }
}

// Check that Person has a type 1 certificate signed by someone
// two certificates from two signers with two signatures with the same expiration date, saying that at current_timestamp a person born at bdate is human
fn main(
    person: pub Person,
    expiration: Field,
    birthdate: Field,
    signers: [ Person; 2],
    signature: [ Signature; 2],
    trust_kernel_root: pub Field,
    signers_hash_path: [HashPath; 2],
    current_timestamp: pub Field
) {
    // verify that the certificates are valid
    assert(current_timestamp.lt(expiration));

    // by type=1 we mean, at the moment, birth certificate
    let certificate = Certificate {
        person: person,
        expiration: expiration,
        cert_type: 1,
        birthdate: birthdate
    };

    // verify first signature
    let verify_signature_1 = dep::std::eddsa::eddsa_poseidon_verify(signers[0].x, signers[0].y, signature[0].s, signature[0].rx, signature[0].ry, certificate.hash());
    let verify_signature_2 = dep::std::eddsa::eddsa_poseidon_verify(signers[1].x, signers[1].y, signature[1].s, signature[1].rx, signature[1].ry, certificate.hash());

    // calculate the merkle root of the signers with their hash paths
    let leaf_signer1 : Field = std::hash::pedersen_hash([signers[0].x, signers[0].y]);
    let leaf_signer2 : Field = std::hash::pedersen_hash([signers[1].x, signers[1].y]);

    let merkel_root1 = std::merkle::compute_merkle_root(leaf_signer1, signers_hash_path[0].index, signers_hash_path[0].path);
    let merkel_root2 = std::merkle::compute_merkle_root(leaf_signer2, signers_hash_path[1].index, signers_hash_path[1].path);

    // verify the signers are in the merkle roots
    assert(merkel_root1 == trust_kernel_root);
    assert(merkel_root2 == trust_kernel_root);

    // Check the signatures are correct
    assert(verify_signature_1);
    assert(verify_signature_2);
}