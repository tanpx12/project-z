use std::str::FromStr;

use cosmwasm_std::Coin;
use cw_storage_plus::{Item, Map, PkOwned};

use zportal::merkle_tree::MerkleTreeWithHistory;
use zportal::verifier::Verifier;

use num256::Uint256 as U256;

pub type KEY = [u8; 32];

pub const BASE_COIN: Item<Coin> = Item::new("base_coin");

pub const VERIFIER: Item<Verifier> = Item::new("VERIFIER");

pub const COMMITMENTS: Item<MerkleTreeWithHistory> = Item::new("COMMITMENTS");

pub const NULLIFIER_HASHES: Map<PkOwned, bool> = Map::new("NULLIFIER_HASHES");

pub fn key_from_string(s: String) -> PkOwned {
    let x = U256::from_str(&s).unwrap();
    return PkOwned(x.to_bytes_le());
}

// pub fn uint256_to_bytes_le(x: U256) -> [u8; 32] {
//     let mut ans = [0u8; 32];
//     let vec = x.to_bytes_le();
//     for i in 0..vec.len() {
//         ans[i] = vec[i];
//     }

//     return ans
// }