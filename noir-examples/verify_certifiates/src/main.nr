mod data_processing;

use dep::std;
use data_processing::bytes_to_fields;

// Check that Person has a type 1 certificate signed by someone
// two certificates from two signers with two signatures with the same expiration date, saying that at current_timestamp a person born at bdate is human
fn main(
    person: pub [Field; 2],
    signers: [ [Field; 2]; 2], 
    signature: [ [Field; 3]; 2],
    expiration: Field, 
    bdate: Field,
    trust_kernel_root: pub Field,
    signers_merkle_hash_path : [ [Field; 2]; 2],
    signers_merkle_hash_path_index: [Field; 2],
    current_timestamp: pub Field
) {
    // verify that the certificates are valid 
    assert(current_timestamp.lt(expiration));

    // turn everything into bytes
    let person_bytes: [[u8; 64]; 2] = [field_to_hex_bytes(person[0]), field_to_hex_bytes(person[1])];
    let expiration_bytes: [u8; 10] = field_to_bytes(expiration); 
    let bdate_bytes: [u8; 10] = field_to_bytes(bdate); 

    let cert_type : u8 = 49; // 49 = "1" in bytes

    let certificate_bytes : [u8; 192] = build_certificate(person_bytes[0], person_bytes[1], cert_type, expiration_bytes, bdate_bytes);

    // Transfer the certificate into an array of Field elements
    let certificate_fields: [Field; 7] = bytes_to_fields(certificate_bytes).0;

    // // Calculate Poseidon Hash
    let certificate_hash = dep::std::hash::poseidon::bn254::hash_7(certificate_fields);

    // verify first signature
    let verify_signature_1 = dep::std::eddsa::eddsa_poseidon_verify(signers[0][0], signers[0][1], signature[0][0], signature[0][1], signature[0][2], certificate_hash);
    let verify_signature_2 = dep::std::eddsa::eddsa_poseidon_verify(signers[1][0], signers[1][1], signature[1][0], signature[1][1], signature[1][2], certificate_hash);

    // calculate the merkle root of the signers with their hash paths
    let leaf_signer1 : Field = std::hash::pedersen_hash([signers[0][0], signers[0][1]]);
    let leaf_signer2 : Field = std::hash::pedersen_hash([signers[1][0], signers[1][1]]);

    let merkel_root1 = std::merkle::compute_merkle_root(leaf_signer1, signers_merkle_hash_path_index[0], signers_merkle_hash_path[0]);
    let merkel_root2 = std::merkle::compute_merkle_root(leaf_signer2, signers_merkle_hash_path_index[1], signers_merkle_hash_path[1]);

    // verify the signers are in the merkle roots
    assert(merkel_root1 == trust_kernel_root);
    assert(merkel_root2 == trust_kernel_root);

    // Check the signatures are correct
    assert(verify_signature_1);
    assert(verify_signature_2);
}

unconstrained fn field_to_bytes<N>(field: Field) -> [u8; N] {
    let slice = field.to_be_radix(10, N);
    let mut bytes: [u8; N] = [0; N];
    for i in 0..N {
        bytes[i] = slice[i] + 48;
    }

    bytes
}

unconstrained fn field_to_hex_bytes<N>(field: Field) -> [u8; N] {
    let slice = field.to_be_radix(16, N);
    let mut bytes: [u8; N] = [0; N];
    for i in 0..N {
        if slice[i] < 10 {
            // for digits add 48 to get string character
            bytes[i] = slice[i] + 48;
        } else {
            // for a-f letters add 48 to get string character
            bytes[i] = slice[i] + 87;
        }
    }

    bytes
}

unconstrained fn build_certificate(
    person_x_bytes: [u8; 64], 
    person_y_bytes: [u8; 64], 
    cert_type: u8, 
    expiration: [u8; 10], 
    bdate: [u8; 10]
) -> [u8; 192] {
    let mut certificate_bytes: [u8; 192] = [0; 192];

    certificate_bytes[0] = selected_strings(1); //{
    certificate_bytes[1] = selected_strings(4); //"
    certificate_bytes[2] = 120; //x
    certificate_bytes[3] = selected_strings(4); //"
    certificate_bytes[4] = selected_strings(5); //:
    certificate_bytes[5] = selected_strings(4); //"

    certificate_bytes[70] = selected_strings(4); //" -> close "x"
    certificate_bytes[71] = selected_strings(3);//,
    certificate_bytes[72] = selected_strings(4);//"
    certificate_bytes[73] = 121; //y
    certificate_bytes[74] = selected_strings(4);//"
    certificate_bytes[75] = selected_strings(5);//:
    certificate_bytes[76] = selected_strings(4); //"

    certificate_bytes[141] = selected_strings(4); //" -> close "y"
    certificate_bytes[142] = selected_strings(3);//,
    certificate_bytes[143] = selected_strings(4);//"
    certificate_bytes[144] = 116; // t
    certificate_bytes[145] = 121; // y
    certificate_bytes[146] = 112; // p
    certificate_bytes[147] = 101; // e
    certificate_bytes[148] = selected_strings(4);//"
    certificate_bytes[149] = selected_strings(5);//:
    certificate_bytes[150] = cert_type;
    certificate_bytes[151] = selected_strings(3);//,
    certificate_bytes[152] = selected_strings(4);//"
    certificate_bytes[153] = 101; // e
    certificate_bytes[154] = 120; // x
    certificate_bytes[155] = 112; // p
    certificate_bytes[156] = 100; // d
    certificate_bytes[157] = 97;  // a
    certificate_bytes[158] = 116; // t
    certificate_bytes[159] = 101; // e
    certificate_bytes[160] = selected_strings(4);//"
    certificate_bytes[161] = selected_strings(5);//:

    certificate_bytes[172] = selected_strings(3);//,
    certificate_bytes[173] = selected_strings(4);//"
    certificate_bytes[174] = 98;  // b
    certificate_bytes[175] = 100; // d
    certificate_bytes[176] = 97;  // a
    certificate_bytes[177] = 116; // t
    certificate_bytes[178] = 101; // e
    certificate_bytes[179] = selected_strings(4);//"
    certificate_bytes[180] = selected_strings(5);//:

    certificate_bytes[191] = selected_strings(2); //}

    // fill in 'x' and 'y'
    for i in 0..64 {
        certificate_bytes[i+6] = person_x_bytes[i];
        certificate_bytes[i+77]= person_y_bytes[i];
    }

    // fill in 'expdate' שמג 'bdate'
    for i in 0..10 {
        certificate_bytes[i+162] = expiration[i];
        certificate_bytes[i+181]= bdate[i];
    }

    certificate_bytes
}

// 1 - '{'. 2-'}', 3=',', 4='"', 5=':'  
unconstrained fn selected_strings(ch: u8) -> u8 {
    let mut ascii : u8 = 0;

    if ch == 1 {
        ascii = 123;
    }

    if ch == 2 {
        ascii = 125;
    }

    if ch == 3 {
        ascii = 44;
    }

    if ch == 4 {
        ascii = 34;
    }

    if ch == 5 {
        ascii = 58;
    }

    // return an error
    ascii
}
