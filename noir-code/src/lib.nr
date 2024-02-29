mod data_processing;

use data_processing::bytes_to_fields;

pub fn message_to_fields<N,M>(msg: str<N>) -> ([Field; M], u32)
{
    bytes_to_fields(msg.as_bytes())
}

#[test]
fn hello_poseidon()
{
    let msg: str<59> = "This is a run-through of the Poseidon permutation function.";
    let fields: [Field; 2] = message_to_fields(msg).0;
    let hash = dep::std::hash::poseidon::bn254::hash_2(fields);
    assert(hash == 0x0b5de89054f5ff651f919eb397f4a125e9ba2aebd175dd809fe8fd02569d8087);
}
