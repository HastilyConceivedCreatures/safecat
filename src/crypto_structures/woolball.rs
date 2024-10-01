use crate::crypto_structures::babyjubjub::{self, Fq};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct WoolballName {
    pub name: String,
}

impl WoolballName {
    pub fn id(&self) -> Fq {
        babyjubjub::woolball_name_to_fq(&self.name).unwrap()
    }

    pub fn to_fq_vec(&self) -> Vec<Fq> {
        vec![self.id()]
    }
}
