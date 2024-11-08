use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerklePederson {
    pub root: String,
    pub leaves: Vec<Leaf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Leaf {
    pub leaf: String,

    pub index: u32,

    pub path: Vec<String>,
}
