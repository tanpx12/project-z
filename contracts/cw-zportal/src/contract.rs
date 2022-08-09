#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;

use cosmwasm_std::{
    to_binary, BankMsg, Binary, Coin, Deps, DepsMut, Env, MessageInfo, InitResponse, HandleResponse, StdResult,
    Uint128 as U128,
    attr, CosmosMsg 
};

use bignumber::Uint256 as U256;

// use cw_utils::must_pay;

use std::str::FromStr;

use cw2::set_contract_version;

use zportal::merkle_tree::MerkleTreeWithHistory;
use zportal::msg::PublicSignals;
use zportal::verifier::Verifier;

use crate::error::{ContractError, PaymentError};
use crate::msg::{DepositMsg, ExecuteMsg, InstantiateMsg, IsKnownRootMsg, QueryMsg, WithdrawMsg};
use crate::state::{BASE_COIN, COMMITMENTS, NULLIFIER_HASHES, VERIFIER, key_from_string};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:orai-zportal";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn init(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<InitResponse> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    BASE_COIN.save(deps.storage, &Coin::new(msg.amount.u128(), msg.denom))?;

    let verifier = Verifier::new(r#"{
        "IC": [
          [
            "21726226774139070258214887671911321975735061870319425296750778337144292428884",
            "18246567690380915940131324997221190289084652680248086081724770702667893075653",
            "1"
          ],
          [
            "21016585187034943544276308301993009643435020173699305266857202546185712101052",
            "1958122134473116582133928891193463404253672897995444847308862754736349746017",
            "1"
          ],
          [
            "7662492830103806644569361641388651061924115783891857174593005311579717340204",
            "149945271670887960110299967394718453997640518490748076951765658673459396993",
            "1"
          ],
          [
            "19145794651963509990879844763827386145926591169857318992851889242951962969096",
            "2051632731071827765462204210827918050178937714071730818364685666967887936789",
            "1"
          ],
          [
            "16497642507332618970347503339494970774651862225352909971536814820558601434822",
            "8607295773286527409637974498539847446116904759380437484276234795056714368167",
            "1"
          ],
          [
            "21335780409584216755421747028082403805651487054625292271050875592276108530220",
            "586774942865210508983827012937811773895043623014426457346955316766213451787",
            "1"
          ]
        ],
        "vk_alfa_1": [
          "19876798840573311052069781186326120753744355548007765401648994479882501529977",
          "7356109404332404382729353805016470521148116312688330465740236442673733585995",
          "1"
        ],
        "vk_alpha_1": [
          "19876798840573311052069781186326120753744355548007765401648994479882501529977",
          "7356109404332404382729353805016470521148116312688330465740236442673733585995",
          "1"
        ],
        "vk_beta_2": [
          [
            "14179114877070894035632731726766731005374968151351526797219352160032008464890",
            "16398642870351178291450657625073361200678436874534056712938024383022261555896"
          ],
          [
            "17033053272038781979683198754428392212782290453507472078507380839431051567494",
            "10337241587219541641241182808123954873012138997719107081951461320020151686250"
          ],
          [
            "1",
            "0"
          ]
        ],
        "vk_gamma_2": [
          [
            "5544679135959590037932335726593875135209463657683405700292235057412152885327",
            "10745446469143255202531860330734993146380816885893469436029648181114870152244"
          ],
          [
            "6988358823759920853596987205528425562240962991232120124993163629840589523050",
            "4266308987333946215532787172735584115611420295790039468554398529618231341098"
          ],
          [
            "1",
            "0"
          ]
        ],
        "vk_delta_2": [
          [
            "15708678521563087178960173030811545417334006901345410718051752851717266625464",
            "17554461083352969011853646966917016144465093930274163979325377124576974149355"
          ],
          [
            "11626666774284381278588353137896612524334256942372606690907887083383595102217",
            "8159721236713010563735164933250847425537231021329554657166092857049292291773"
          ],
          [
            "1",
            "0"
          ]
        ],
        "vk_alfabeta_12": [
          [
            [
              "16559256307195556909684878276726820400492278207220606721520155785961949080057",
              "14523462861745885142136099751203223082808782870931618262158862059053168926551"
            ],
            [
              "19919738229809492086265683856973231266567056456152182126142234327518644101949",
              "15784103204193828475982277126738364134320325614103921158216604501641103516179"
            ],
            [
              "1845925078417042599326634415215775874291583551089733857092599342492204163588",
              "13689912852929415408706567121856747195006578307879215006546271523186252880433"
            ]
          ],
          [
            [
              "9156916387089854685373850396993489380759295892065500773004989912873733505141",
              "1130975499460127532001169640609782504474427458173748554695780783423184640577"
            ],
            [
              "4176924627295241951223635591487701947971879635548749676418321412716167470369",
              "4529464718635973552965996776537741532230527559081840903362626384578820333452"
            ],
            [
              "15547641929889288950045542019394887684095703118126459025189400834345124899650",
              "19596529875043857726330297405663009176599556253576817870817079663977572353418"
            ]
          ]
        ],
        "vk_alphabeta_12": [
          [
            [
              "16559256307195556909684878276726820400492278207220606721520155785961949080057",
              "14523462861745885142136099751203223082808782870931618262158862059053168926551"
            ],
            [
              "19919738229809492086265683856973231266567056456152182126142234327518644101949",
              "15784103204193828475982277126738364134320325614103921158216604501641103516179"
            ],
            [
              "1845925078417042599326634415215775874291583551089733857092599342492204163588",
              "13689912852929415408706567121856747195006578307879215006546271523186252880433"
            ]
          ],
          [
            [
              "9156916387089854685373850396993489380759295892065500773004989912873733505141",
              "1130975499460127532001169640609782504474427458173748554695780783423184640577"
            ],
            [
              "4176924627295241951223635591487701947971879635548749676418321412716167470369",
              "4529464718635973552965996776537741532230527559081840903362626384578820333452"
            ],
            [
              "15547641929889288950045542019394887684095703118126459025189400834345124899650",
              "19596529875043857726330297405663009176599556253576817870817079663977572353418"
            ]
          ]
        ],
        "curve": "BN254",
        "protocol": "groth",
        "nPublic": 5
      }"#.to_string());

    VERIFIER.save(deps.storage, &verifier)?;

    let tree = MerkleTreeWithHistory::new(20);
    COMMITMENTS.save(deps.storage, &tree)?;

    Ok(InitResponse::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn handle(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<HandleResponse, ContractError> {
    match msg {
        ExecuteMsg::Deposit(msg) => execute_deposit(deps, info, msg),
        ExecuteMsg::Withdraw(msg) => execute_withdraw(deps, env, info, msg),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::IsKnownRoot(msg) => to_binary(&query_is_known_root(deps, msg)?),
    }
}

pub fn query_is_known_root(deps: Deps, msg: IsKnownRootMsg) -> StdResult<bool> {
    let commitment_mt = COMMITMENTS.load(deps.storage)?;

    Ok(commitment_mt.is_known_root(&U256::from_str(&msg.root).unwrap()))
}

pub fn must_pay(info: &MessageInfo, denom: &str) -> Result<U128, PaymentError> {
    let coin = one_coin(info)?;
    if coin.denom != denom {
        Err(PaymentError::MissingDenom(denom.to_string()))
    } else {
        Ok(coin.amount)
    }
}

pub fn one_coin(info: &MessageInfo) -> Result<Coin, PaymentError> {
    match info.sent_funds.len() {
        0 => Err(PaymentError::NoFunds {}),
        1 => {
            let coin = &info.sent_funds[0];
            if coin.amount.is_zero() {
                Err(PaymentError::NoFunds {})
            } else {
                Ok(coin.clone())
            }
        }
        _ => Err(PaymentError::MultipleDenoms {}),
    }
}


pub fn execute_deposit(
    deps: DepsMut,
    info: MessageInfo,
    msg: DepositMsg,
) -> Result<HandleResponse, ContractError> {
    let coin = BASE_COIN.load(deps.storage)?;

    let payment = must_pay(&info, &coin.denom)?;
    if payment != coin.amount {
        return Err(ContractError::InvalidAmount {
            denom: coin.denom,
            amount: coin.amount,
        });
    }

    let mut commitment_mt = COMMITMENTS.load(deps.storage)?;
    // TODO: confirm insert worked
    commitment_mt.insert(&U256::from_str(&msg.commitment).unwrap());
    COMMITMENTS.save(deps.storage, &commitment_mt)?;

    // Ok(Response::new()
    //     .add_attribute("action", "deposit")
    //     .add_attribute("from", info.sender))

    return Ok(HandleResponse {
        messages: vec![],
        attributes: vec![
            attr("action", "deposit"),
            attr("from", info.sender),
            attr("commitment", msg.commitment)
        ],
        data: None
    })
}

pub fn execute_withdraw(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: WithdrawMsg,
) -> Result<HandleResponse, ContractError> {
    let coin = BASE_COIN.load(deps.storage)?;
    // TODO: check info.funds

    let public_signals = PublicSignals::from_values(
        msg.root.clone(),
        msg.nullifier_hash.clone(),
        msg.recipient.clone().to_string(),
        msg.relayer.clone().to_string(),
        msg.fee,
    );

    let commitment_mt = COMMITMENTS.load(deps.storage)?;
    assert_ne!(
        commitment_mt.current_root_index, 0,
        "commitment merkle tree shouldn't be 0"
    );

    // 1. check nullifier_hash is not in nullifier hashes

    match NULLIFIER_HASHES.may_load(deps.storage, key_from_string( msg.nullifier_hash.clone()))? {
        Some(_) => return Err(ContractError::DuplicatedCommitment {}),
        None => (),
    };

    // 2. confirm root is ok
    if !commitment_mt.is_known_root(&U256::from_str(&msg.root).unwrap()) {
        return Err(ContractError::UnknownRoot {});
    }

    // 3. Confirm the circuit proof
    let verifier = VERIFIER.load(deps.storage)?;
    let proof = msg.proof.to_proof();
    let inputs = public_signals.get();
    if !verifier.verify_proof(proof, &inputs) {
        return Err(ContractError::InvalidProof {});
    };

    // 4. Store nullifier hash to nullifier_hashes map
    NULLIFIER_HASHES
        .save(deps.storage, key_from_string( msg.nullifier_hash.clone()), &true)
        .unwrap();

    // 5. Send the funds
    let mut msgs: Vec<CosmosMsg> = Vec::new();

    let amount_to_recipient = match coin.amount - (U128::from(msg.fee)) {
        Ok(v) => v,
        Err(err) => {
            return Err(ContractError::FeesTooHigh {
                msg: err.to_string(),
            })
        }
    };

    msgs.push(CosmosMsg::Bank( BankMsg::Send {
        from_address: env.contract.address.clone(),
        to_address: msg.recipient,
        amount: vec![Coin {
            denom: coin.denom.clone(),
            amount: amount_to_recipient,
        }],
    }));
    if !msg.fee.is_zero() {
        msgs.push(CosmosMsg::Bank( BankMsg::Send {
            from_address: env.contract.address,
            to_address: msg.relayer,
            amount: vec![Coin {
                denom: coin.denom.clone(),
                amount: msg.fee,
            }],
        }));
    }

    // Ok(Response::new()
    //     .add_messages(msgs)
    //     .add_attribute("action", "withdraw"))
    
    return Ok(HandleResponse {
        messages: msgs,
        attributes: vec![
            attr("action", "withdraw")
        ],
        data: None
    })
}

// #[cfg(test)]
// mod tests {
//     use cosmwasm_std::coins;
//     use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};

//     use zportal::msg::Deposit;

//     use super::*;

//     #[test]
//     fn test_deposit() {
//         let mut deps = mock_dependencies(&[]);
//         let info = mock_info(&"Alice".to_string(), &coins(10, "TKN"));

//         // let deposit = generate_deposit();
//         let deposit = Deposit::new(
//             "276277773929387392791096474084808108569850403587654342680891529007770412737"
//                 .to_string(),
//         );

//         // instantiate an empty contract
//         let instantiate_msg = InstantiateMsg {
//             amount: U128::from(10 as u128),
//             denom: "TKN".to_string(),
//         };
//         let res = instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap();
//         assert_eq!(0, res.messages.len());

//         let deposit_msg = DepositMsg {
//             commitment: deposit.get_commitment(),
//         };

//         let msg = ExecuteMsg::Deposit(deposit_msg.clone());

//         let info = mock_info(&"Alice".to_string(), &coins(10, "TKN"));
//         let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
//         assert_eq!(0, res.messages.len());
//     }

//     #[test]
//     fn test_withdraw_1() {
//         let mut deps = mock_dependencies(&[]);

//         // instantiate an empty contract
//         let instantiate_msg = InstantiateMsg {
//             amount: U128::from(10 as u128),
//             denom: "TKN".to_string(),
//         };
//         let info = mock_info(&"Alice".to_string(), &[]);

//         let res = instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap();
//         assert_eq!(0, res.messages.len());

//         let mut tree = COMMITMENTS.load(&deps.storage).unwrap();

//         let deposit = Deposit {
//             nullifier: "54154714943715201094961901040590459639892306160131965986154511512546000403"
//                 .to_string(),
//         };

//         let leaf_index = tree
//             .insert(&U256::from_str(&deposit.clone().get_commitment()).unwrap())
//             .unwrap();

//         COMMITMENTS.save(&mut deps.storage, &tree).unwrap();

//         let msg = ExecuteMsg::Withdraw(WithdrawMsg {
//             proof: zportal::msg::CircomProof::from(
//                 r#"
//                 {"pi_a":["10629758862435853336945712117365103618272561056222019226240806118776225405212","12094755642641665221239115629983657286997314809894229129628714990758791466153","1"],"pi_b":[["11186157756116738617053057611111849877248438998886057219898994284672755095787","12497766681974579924875671812236126385677528573379010403478863950922377556831"],["9825673020471505445480714951954464271247928778089895856571011843453336870912","1022732429585413494420382850054446238745583774340722512919058267306851086471"],["1","0"]],"pi_c":["5729347437989247454415384578737747309694582158917085398061374511631507193068","3624008422587939009694034717028437650283952293646457543503996693929528088247","1"],"protocol":"groth16","curve":"bn128"}
//                 "#.to_string(),
//             ),
//             root: "7867364560627547019086598689541673085228895175200585554350937642876639323043".to_string(),
//             nullifier_hash: deposit.get_nullifier_hash((leaf_index) as u128),
//             recipient: "juno14spgzl9ps5tyev32ny74fa6m0s9q9828v0vrga".to_string(),
//             relayer: "juno1am5sw4geda8xfvmn4pkzruhv8ah0l3jx5hgchh".to_string(),
//             fee: U128::from(0 as u128),
//         });
//         let info = mock_info(&"Alice".to_string(), &[]);

//         let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
//         assert_eq!(1, res.messages.len());
//     }

//     // #[test]
//     // fn test_withdraw_20() {
//     //     let mut deps = mock_dependencies();

//     //     let deposit = Deposit::from_note("juno-zportal-86ca9e972ed3784d9407f431e045be9b3c3c913327b0d3a669edce2ef1399f13578e9a6ae07cd5bc749d41c33b03e876906fb36803508bec87c86ce5b142".to_string());
//     //     COMMITMENTS
//     //         .save(&mut deps.storage, deposit.clone().get_commitment(), &true)
//     //         .unwrap();

//     //     for _ in 0..20 {
//     //         let d = Deposit::new();
//     //         COMMITMENTS
//     //             .save(&mut deps.storage, d.get_commitment(), &true)
//     //             .unwrap();
//     //     }

//     //     // instantiate an empty contract
//     //     let instantiate_msg = InstantiateMsg {
//     //         amount: 10,
//     //         denom: "TKN".to_string(),
//     //     };
//     //     let info = mock_info(&"Alice".to_string(), &[]);

//     //     let res = instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap();
//     //     assert_eq!(0, res.messages.len());

//     //     let msg = ExecuteMsg::Withdraw(WithdrawMsg {
//     //         note: "juno-zportal-86ca9e972ed3784d9407f431e045be9b3c3c913327b0d3a669edce2ef1399f13578e9a6ae07cd5bc749d41c33b03e876906fb36803508bec87c86ce5b142".to_string()
//     //     });
//     //     let info = mock_info(&"Alice".to_string(), &[]);

//     //     let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
//     //     assert_eq!(1, res.messages.len());

//     //     assert!(false);
//     // }
// }
