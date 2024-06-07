#[derive(Debug)]
pub enum Field {
    Name(String),
    Timestamp(SystemTime),
    Age(u32),
    Hash(Vec<u8>),
    PublicKey(Vec<u8>),
}

struct Cert {}

// cert.hash
// cert has a vector of Fields
// cert has to/body/expiration
