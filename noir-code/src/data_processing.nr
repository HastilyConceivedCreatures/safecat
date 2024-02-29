pub(crate) fn bytes_to_fields<N,M>(bs: [u8; N]) -> ([Field; M], u32)
{
    let mut split_bytes = [[0; 32]; M];

    let mut outer_b_ptr = M-1;
    let mut inner_b_ptr = 31;
        
    for i in 0..N
    {
        split_bytes[outer_b_ptr][inner_b_ptr] = bs[N - 1 - i];
        
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
    
    (split_bytes.map(|bs| dep::std::field::bytes32_to_field(bs)), M - outer_b_ptr)
}

#[test]
fn byte_packing_test()
{
    let bytes = [1,2,3];
    let (fields, len): ([Field; 1], u32) = bytes_to_fields(bytes);
    assert(len == 1);
    assert(fields[0] == 0x010203);

    let bytes = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63];
    let (fields, len): ([Field; 3], u32) = bytes_to_fields(bytes);
    assert(len == 3);
    assert(fields[0] == 0x0001);
    assert(fields[1] == 0x02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20);
    assert(fields[2] == 0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f);
}

pub(crate) fn foldr<Env, B,C,N>(f: fn[Env](B,C) -> C, c: C, bs: [B; N]) -> C
{
    let mut acc = c;

    for i in 0..N
    {
        acc = f(bs[N - 1 - i], acc);
    }

    acc
}
