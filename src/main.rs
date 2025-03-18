use std::io::Read;

use sha2::*;

// Use a KDF algorithm in the future
fn derive_key<'a>(key: String) -> Vec<u8> {
    let mut hasher = Sha256::new();

    hasher.update(key.as_bytes());

    hasher.finalize()[..8].to_vec()
}

fn main() {
    let message = "My message is here";
    // make sure to make it 64 bit (padding?)
    let key = "encryption-key".to_string();
    let derived_key = derive_key(key);

    println!("{:?}", derived_key);

    // apply initial permutation

    // inverse permutatin
}
