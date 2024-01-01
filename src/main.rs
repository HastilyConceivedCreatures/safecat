use babyjubjub_ark::{Point, new_key};

fn main() {
    // Initialize a random number generator (you may want to use a proper RNG implementation)
    let mut rng = rand::thread_rng();

    // Generate a new private key
    let private_key = new_key(&mut rng);

    // Compute the corresponding public key
    let public_key: Point = private_key.public();

    // extract the arrays form the keys
    let private_key_something_bigint = private_key.scalar_key().0;
    let private_key_arr : [u64; 4] = private_key.scalar_key().0.0;
    let public_key_x_arr: [u64; 4] = public_key.x.0.0;
    let public_key_y_arr: [u64; 4] = public_key.y.0.0;

    let private_key_something_bigint_hex = format!("{private_key_something_bigint:X}");

    println!("private key something: {:?}", private_key_something_bigint_hex);

    print_u64_array(&private_key_arr);

    print!("x: ");
    print_u64_array(&public_key_x_arr);

    print!("y: ");
    print_u64_array(&public_key_y_arr);
}

fn print_u64_array(arr: &[u64]) {
    for &element in arr {
        print!("{}", element);
    }

    println!("");
}

