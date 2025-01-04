use sha2::{Sha256, Digest};

fn main() {
    // The input data to be hashed
    let data = "Hello, Rust!";

    // Create a Sha256 object
    let mut hasher = Sha256::new();

    // Add data to the hasher
    hasher.update(data);

    // Compute the hash
    let result = hasher.finalize();

    // Convert the result to a hexadecimal string
    let hash_hex = format!("{:x}", result);

    // Print the SHA-256 hash
    println!("Input data: {}", data);
    println!("SHA-256 hash: {}", hash_hex);
}
