// A society is a collection of trusted members.
// It is identified by the root of its merkle tree, where the leaves are the members.
#[derive(Serialize, Deserialize, Debug)]
struct Society {
    root: String,
    members: Vec<MemberSociety>,
}

// A member in a spcific society
#[derive(Serialize, Deserialize, Debug, Clone)]
struct MemberSociety {
    name: String,
    x: String,
    y: String,
    index: u32,        // Merkle proof index
    path: Vec<String>, // Merkle proof path
}
