/// Unit tests for the Safecat

/// Test for the byte packing functionality
#[test]
fn byte_packing_test() {
    // Test case 1: Single field from 3 bytes
    let bytes: &[u8] = &[0x01, 0x02, 0x03];
    let fields = cast::bytes_to_fields(bytes);
    assert!(fields.len() == 1);
    assert!(fields[0] == Fq::from_str(&cast::hex_to_dec("0x010203")).unwrap());

    // Test case 2: Multiple fields from 64 bytes
    let bytes: Vec<u8> = (0..64).collect();
    let fields = cast::bytes_to_fields(&bytes);
    assert!(fields.len() == 3);
    assert!(fields[0] == Fq::from_str(&cast::hex_to_dec("0x0001")).unwrap());
    assert!(
        fields[1]
            == Fq::from_str(&cast::hex_to_dec(
                "0x02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
            ))
            .unwrap()
    );
    assert!(
        fields[2]
            == Fq::from_str(&cast::hex_to_dec(
                "0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            ))
            .unwrap()
    );
}

/// Test for the Poseidon hash functionality
#[test]
fn test_poseidon_hash() {
    let msg = "This is a run-through of the Poseidon permutation function.";
    let hash = calculate_hash_fq(msg, "poseidon");
    assert!(
        hash == Fq::from_str(&cast::hex_to_dec(
            "0x0b5de89054f5ff651f919eb397f4a125e9ba2aebd175dd809fe8fd02569d8087"
        ))
        .unwrap()
    );
}