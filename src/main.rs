use std::io::Read;

use sha2::*;

type BlockSize = u64;

#[rustfmt::skip]
const IP_TABLE: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
];
#[rustfmt::skip]
const IP_INV_TABLE: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25,
];
#[rustfmt::skip]
const KEY_SHIFTS: [u8; 16] = [
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
];
#[rustfmt::skip]
const FIRST_KEY_PERM_TABLE: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
];

// Use a KDF algorithm in the future
fn derive_key<'a>(key: String) -> BlockSize {
    let mut hasher = Sha256::new();

    hasher.update(key.as_bytes());

    u64::from_le_bytes(hasher.finalize()[..8].try_into().unwrap())
}

fn run_permutation(data: BlockSize, table: &[u8; 64]) -> BlockSize {
    let mut pos = 0;
    let mut permutation: BlockSize = 0;

    for start_bit in table {
        let bit = (data >> (start_bit - 1)) & 1;
        permutation += bit << pos; // LSB
        pos += 1;
    }

    permutation
}

fn first_key_permutation(key: BlockSize) -> u64 {
    let mut pos = 0;
    let mut permutation: BlockSize = 0;

    for start_bit in FIRST_KEY_PERM_TABLE {
        let bit = (key >> (start_bit - 1)) & 1;
        permutation += bit << pos; // LSB
        pos += 1;
    }

    permutation
}

fn main() {
    let message = "My message is here";
    // make sure to make it 64 bit (padding?)
    let key = "encryption-key".to_string();
    let derived_key = derive_key(key);

    let b: u64 = 3212;
    let perm = run_permutation(b, &IP_TABLE);
    let inverse_perm = run_permutation(perm, &IP_INV_TABLE);
    let key_perm = first_key_permutation(derived_key);

    println!("{}", inverse_perm);
    println!("{}", key_perm);

    // apply initial permutation

    // inverse permutatin
}
