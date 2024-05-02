// Convert an array of bytes into an array of `Field` elements, ('[Field; M]'),
// along with the number of valid `Field` elements (`u32`).
pub(crate) fn bytes_to_fields<N,M>(bs: [u8; N]) -> ([Field; M], u32)
{
    // Create an array of `M` arrays of 32 bytes, all initialized to 0
    let mut split_bytes = [[0; 32]; M];

    // Initialize pointers for iteration
    let mut outer_b_ptr = M-1;
    let mut inner_b_ptr = 31;
        
    // Iterate over the input byte array
    for i in 0..N
    {
        // Assign the current byte to the current position in the `split_bytes` array
        split_bytes[outer_b_ptr][inner_b_ptr] = bs[N - 1 - i];
        
        // Update the pointers
        if inner_b_ptr == 1
        {
            outer_b_ptr -= 1;
            inner_b_ptr = 31;
        }
        else
        {
            inner_b_ptr -= 1;
        }
    }
    
    // Convert the `split_bytes` array into an array of `Field` elements
    // and return it along with the number of valid `Field` elements
    (
        split_bytes.map(|bs| dep::std::field::bytes32_to_field(bs)), 
        M - outer_b_ptr
    )
}

// Test function to verify the `bytes_to_fields` function
#[test]
fn byte_packing_test()
{
    // Test case 1: Convert [1, 2, 3] to a single `Field` element
    let bytes = [1,2,3];
    let (fields, len): ([Field; 1], u32) = bytes_to_fields(bytes);
    assert(len == 1);
    assert(fields[0] == 0x010203);

    // Test case 2: Convert a longer byte array to an array of 3 `Field` elements
    let bytes = [
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,
        23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,
        43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63
    ];
    let (fields, len): ([Field; 3], u32) = bytes_to_fields(bytes);
    assert(len == 3);
    assert(fields[0] == 0x0001);
    assert(fields[1] == 0x02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20);
    assert(fields[2] == 0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f);
}