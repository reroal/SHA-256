// Constants used in the SHA-256 algorithm
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// Initial hash values
const INITIAL_HASH: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// Helper functions for bitwise operations
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

fn sigma0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

fn sigma1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

fn delta0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

fn delta1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

// Padding the message
fn pad_message(mut message: Vec<u8>) -> Vec<u8> {
    let original_length = message.len() as u64 * 8; // Message length in bits
    message.push(0x80); // Append 1 bit (as 0x80 in binary)
    while (message.len() % 64) != 56 {
        message.push(0x00); // Pad with zeros
    }
    message.extend_from_slice(&original_length.to_be_bytes()); // Append the length
    message
}

// Process a 512-bit chunk
fn process_chunk(chunk: &[u8], hash: &mut [u32; 8]) {
    // Break chunk into 16 32-bit words
    let mut w = [0u32; 64];
    for (i, word) in chunk.chunks(4).enumerate() {
        w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
    }

    // Extend to 64 words
    for i in 16..64 {
        w[i] = delta1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(delta0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    // Initialize working variables
    let mut a = hash[0];
    let mut b = hash[1];
    let mut c = hash[2];
    let mut d = hash[3];
    let mut e = hash[4];
    let mut f = hash[5];
    let mut g = hash[6];
    let mut h = hash[7];

    // Main compression loop
    for i in 0..64 {
        let temp1 = h
            .wrapping_add(sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let temp2 = sigma0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    // Update the hash values
    hash[0] = hash[0].wrapping_add(a);
    hash[1] = hash[1].wrapping_add(b);
    hash[2] = hash[2].wrapping_add(c);
    hash[3] = hash[3].wrapping_add(d);
    hash[4] = hash[4].wrapping_add(e);
    hash[5] = hash[5].wrapping_add(f);
    hash[6] = hash[6].wrapping_add(g);
    hash[7] = hash[7].wrapping_add(h);
}

// Main SHA-256 function
fn sha256(message: &[u8]) -> [u8; 32] {
    let padded_message = pad_message(message.to_vec());
    let mut hash = INITIAL_HASH;

    // Process each 512-bit chunk
    for chunk in padded_message.chunks(64) {
        process_chunk(chunk, &mut hash);
    }

    // Convert the hash to bytes
    let mut result = [0u8; 32];
    for (i, &value) in hash.iter().enumerate() {
        result[i * 4..(i + 1) * 4].copy_from_slice(&value.to_be_bytes());
    }
    result
}

// Example usage
fn main() {
    let data = b"Hello, Rust!";
    let hash = sha256(data);

    println!("Input: {}", String::from_utf8_lossy(data));
    println!("SHA-256 hash: {:x?}", hash);
}
