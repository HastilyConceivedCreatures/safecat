use crate::crypto_structures::merkle_pederson::MerklePederson;
use serde::{Deserialize, Serialize};

// A society is a collection of trusted members.
// It is identified by the root of its merkle tree, where the leaves are the members.
#[derive(Serialize, Deserialize, Debug)]
pub struct Society {
    pub root: String, // Converted from Fq to String
    pub members: Vec<MemberSociety>,
}

// A member in a specific society
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemberSociety {
    pub x: String,         // Converted from Fq to String
    pub y: String,         // Converted from Fq to String
    pub index: u32,        // Merkle proof index
    pub path: Vec<String>, // Converted from Vec<Fq> to Vec<String>
}

impl Society {
    pub fn from_merkle_pederson(merkle: MerklePederson) -> Self {
        // Ensure the number of leaves is even as per the problem requirements.
        assert!(
            merkle.leaves.len() % 2 == 0,
            "Merkle tree must have an even number of leaves"
        );

        let mut members = Vec::new();

        // Process leaves in pairs to form `MemberSociety`.
        for leaf_pair in merkle.leaves.chunks(2) {
            if let [left_leaf, right_leaf] = leaf_pair {
                // Assign `x` and `y` directly from the leaves.
                let x = left_leaf.leaf.clone();
                let y = right_leaf.leaf.clone();

                // Construct the path by removing the first element.
                let path = left_leaf.path[1..].to_vec();

                // Calculate the index by stripping the most significant bit.
                let index = {
                    let mut index = left_leaf.index;
                    index &= !(1 << 7); // Clear the most significant bit.
                    index
                };

                // Construct `MemberSociety` and add to `members`.
                members.push(MemberSociety { x, y, index, path });
            }
        }

        // Create the Society with the root and members.
        Society {
            root: merkle.root.clone(),
            members,
        }
    }
}
