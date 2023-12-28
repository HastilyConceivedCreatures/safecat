use babyjubjub_ark::{Point, new_key};

fn main() {
    // Initialize a random number generator (you may want to use a proper RNG implementation)
    let mut rng = rand::thread_rng();

    // Generate a new private key
    let private_key = new_key(&mut rng);

    // Compute the corresponding public key
    let public_key: Point = private_key.public();

    // Print the private key and public key
    println!("Private Key: {:?}", private_key.scalar_key());
    println!("Public Key: {:?}", public_key);
}