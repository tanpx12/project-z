use crate::poseidon::Poseidon;

use std::{str::FromStr, convert::TryInto};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ff::{Fp256, QuadExtField};
use ark_groth16::Proof;

use cosmwasm_std::{Uint128 as U128};
use bignumber:: Uint256 as U256;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PublicSignals(pub Vec<String>);

// Public signals from circom
// public [root, nullifierHash, recipient, relayer, fee]
impl PublicSignals {
    pub fn from(public_signals: Vec<String>) -> Self {
        PublicSignals(public_signals)
    }
    pub fn from_values(
        root: String,
        nullifier_hash: String,
        recipient: String,
        relayer: String,
        fee: U128,
    ) -> Self {
        let mut signals: Vec<String> = Vec::new();
        signals.push(root);
        signals.push(nullifier_hash);
        signals.push(PublicSignals::bech32_to_u256(recipient));
        signals.push(PublicSignals::bech32_to_u256(relayer));
        signals.push(fee.to_string());

        PublicSignals(signals)
    }
    pub fn from_json(public_signals_json: String) -> Self {
        let v: Vec<String> = serde_json::from_str(&public_signals_json).unwrap();
        PublicSignals(v)
    }

    pub fn get(self) -> Vec<Fr> {
        let mut inputs: Vec<Fr> = Vec::new();
        for input in self.0 {
            inputs.push(Fr::from_str(&input).unwrap());
        }
        inputs
    }

    fn bech32_to_u256(addr: String) -> String {
        if addr == "" || addr == "0" {
            return "0".to_string();
        }
        let (_, payloads, _) = bech32::decode(&addr).unwrap();

        let words: Vec<u8> = payloads.iter().map(|x| x.to_u8()).collect();
        // TODO: take a look at a cleaner way
        U256::from_be_bytes(words.try_into().unwrap()).to_string()
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CircomProof {
    #[serde(rename = "pi_a")]
    pub pi_a: Vec<String>,
    #[serde(rename = "pi_b")]
    pub pi_b: Vec<Vec<String>>,
    #[serde(rename = "pi_c")]
    pub pi_c: Vec<String>,
}

impl CircomProof {
    pub fn from(json_str: String) -> Self {
        serde_json::from_str(&json_str).unwrap()
    }

    pub fn to_proof(self) -> Proof<Bn254> {
        let a = G1Affine::new(
            Fp256::from_str(&self.pi_a[0]).unwrap(),
            Fp256::from_str(&self.pi_a[1]).unwrap(),
            false,
        );
        let b = G2Affine::new(
            QuadExtField::new(
                Fp256::from_str(&self.pi_b[0][0]).unwrap(),
                Fp256::from_str(&self.pi_b[0][1]).unwrap(),
            ),
            QuadExtField::new(
                Fp256::from_str(&self.pi_b[1][0]).unwrap(),
                Fp256::from_str(&self.pi_b[1][1]).unwrap(),
            ),
            false,
        );

        let c = G1Affine::new(
            Fp256::from_str(&self.pi_c[0]).unwrap(),
            Fp256::from_str(&self.pi_c[1]).unwrap(),
            false,
        );
        Proof { a, b, c }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Deposit {
    pub nullifier: String,
}

impl Deposit {
    pub fn new(nullifier: String) -> Deposit {
        Deposit {
            nullifier: nullifier,
            // nullifier: BigUint::to_string(&rbigint(31)),
        }
    }

    pub fn get_commitment(self) -> String {
        let poseidon = Poseidon::new();

        let right = U256::from_str("0").unwrap();

        let nullifier = U256::from_str(&self.nullifier).unwrap();

        let inputs = vec![uint256_to_bytes_le(nullifier), uint256_to_bytes_le(right)];

        let res = poseidon.hash(inputs).unwrap();

        U256::from_le_bytes(res).to_string()
    }

    

    pub fn get_nullifier_hash(self, leaf_index: u128) -> String {
        let poseidon = Poseidon::new();

        let nullifier = U256::from_str(&self.nullifier).unwrap();

        let secret = U256::from(1 as u64);
        let leaf_i = U256::from(leaf_index);

        let inputs = vec![
            uint256_to_bytes_le(nullifier),
            uint256_to_bytes_le(secret),
            uint256_to_bytes_le(leaf_i),
        ];

        let res = poseidon.hash(inputs).unwrap();

        U256::from_le_bytes(res).to_string()
    }

    pub fn commitment_as_array(self) -> [u8; 32] {
        let commitment = self.get_commitment();
        let mut dst: [u8; 32] = [0; 32];
        dst.clone_from_slice(&commitment.as_bytes()[0..32]);
        return dst;
    }
}

#[test]
fn test_generate_deposit() {
    let d = Deposit {
        nullifier: "276277773929387392791096474084808108569850403587654342680891529007770412737"
            .to_string(),
    };

    let commitment = d.clone().get_commitment();

    assert_eq!(
        commitment,
        "6236796047772841813667132166633849358445729975292785870973181152954966652594".to_string()
    );
    assert_eq!(
        d.get_nullifier_hash(0),
        "10174783302134252183272028399003089320089964203118066360883858790559353379370".to_string()
    )
}

pub fn uint256_to_bytes_le(x: U256) -> [u8; 32] {
    let mut ans = [0u8; 32];
    let vec = x.to_le_bytes();
    for i in 0..vec.len() {
        ans[i] = vec[i];
    }

    return ans
}

#[test]
fn test_parse_juno_addr() {
    // 9526846490934353717899961266123756195211556155320547954451400665347450669575
    let recipient = "juno14spgzl9ps5tyev32ny74fa6m0s9q9828v0vrga";

    // from juno1 bech32 address to U256
    {
        let (_, payloads, _) = bech32::decode(recipient).unwrap();
        println!("payloads: {:?}\n", payloads);

        let words: Vec<u8> = payloads.iter().map(|x| x.to_u8()).collect();
        assert_eq!(words.len(), 32);

        let n = U256::from_be_bytes(words.try_into().unwrap());
        assert_eq!(
            n.to_string(),
            "9526846490934353717899961266123756195211556155320547954451400665347450669575"
        );
    }

    // from U256 to bech32
    // {
    //     let data: Vec<bech32::u5> = U256::from_str(
    //         "9526846490934353717899961266123756195211556155320547954451400665347450669575",
    //     )
    //     .unwrap()
    //     .to_bytes_be()
    //     .map(|x| bech32::u5::try_from_u8(x).unwrap())
    //     .to_vec();

    //     let addr = bech32::encode("juno", data, bech32::Variant::Bech32).unwrap();
    //     println!("addr: {}", addr);

    //     assert_eq!(recipient, addr);
    // }
}
