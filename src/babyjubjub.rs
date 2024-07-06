use crate::{bn254_scalar_cast, cast};
pub use ark_bn254::Fr as BN254R;
use babyjubjub_ark::Point;

#[derive(Debug)]
pub struct Pubkey {
    pub x: BN254R,
    pub y: BN254R,
}

/// Str hex is simple concatenating the hex of the x and y of the pubkey
impl Pubkey {
    pub fn from_str_hex(pubkey_str: String) -> Pubkey {
        let pubkey_vec = bn254_scalar_cast::babyjubjub_pubkey_to_bn254(&pubkey_str).unwrap();

        // validate public key input and split it into x and y
        Pubkey {
            x: pubkey_vec[0],
            y: pubkey_vec[1],
        }
    }

    pub fn to_bn254_r(&self) -> Vec<BN254R> {
        vec![self.x, self.y]
    }

    pub fn from_point(point: Point) -> Pubkey {
        let pubkey = Pubkey {
            x: point.x,
            y: point.y,
        };

        pubkey
    }

    pub fn to_str_hex(&self) -> String {
        let hex_string_x: String = cast::fq_to_hex_string(&self.x);
        let hex_string_y: String = cast::fq_to_hex_string(&self.y);

        format!("{}{}", hex_string_x, hex_string_y)
    }
}
