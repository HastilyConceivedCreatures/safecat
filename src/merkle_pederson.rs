#[derive(Debug)]
pub struct Merkle_Pederson {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub root: BN254R,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub members: Vec<Member>,
}

struct Member {
    id: BN254R,
    path_index: Vec<u8>,
    path: Vec<BN254R>,
}
