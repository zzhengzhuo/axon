use std::str::FromStr;

use common_crypto::{
    HashValue, PrivateKey, Secp256k1RecoverablePrivateKey, Signature, ToPublicKey,
    UncompressedPublicKey,
};
use evm::{ExitReason, ExitSucceed};
use primitive_types::{H160, U256};
use protocol::codec::hex_encode;
use protocol::tokio;
use protocol::types::Hasher;
use protocol::{codec::hex_decode, types::TransactionAction};

use crate::debugger::{
    mock_signed_tx,
    uniswap2::{construct_tx, read_code},
    EvmDebugger,
};

ethabi_contract::use_contract!(in_ecrecover, "res/in_ecrecover.abi");

fn deploy_ecrecover(debugger: &mut EvmDebugger, sender: H160, block_number: &mut u64) -> H160 {
    println!("######## Deploy Ecrecover contract");
    let code = hex_decode(&read_code("core/executor/res/in_ecrecover_code.txt")).unwrap();
    // let code = hex_decode(&read_code("res/in_ecrecover_code.txt")).unwrap();
    let tx = construct_tx(TransactionAction::Create, U256::default(), code);
    let stx = mock_signed_tx(tx, sender);

    let resp = debugger.exec(*block_number, vec![stx]);
    println!("{:?}", resp);
    assert_eq!(
        resp.tx_resp[0].exit_reason,
        ExitReason::Succeed(ExitSucceed::Returned)
    );

    *block_number += 1;

    let code_address = resp.tx_resp[0].code_address.unwrap().0;
    H160::from_slice(&code_address[12..])
}

const ETH_PREFIX: &[u8; 28] = &[
    0x19, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64,
    0x20, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x3a, 0x0a, 0x33, 0x32,
];

#[tokio::test(flavor = "multi_thread")]
async fn test_ecrecover() {
    println!("current dir: {:?}", std::env::current_dir());
    let distribution_address =
        H160::from_str("0x3f17f1962b36e491b30a40b2405849e597ba5fb5").unwrap();
    let distribution_amount: U256 = 1234560000000000000000000u128.into();
    let db_path = "core/executor/free-space/db0";
    // let db_path = "./free-space/db0";

    let mut debugger = EvmDebugger::new(distribution_address, distribution_amount, db_path);
    let sender = distribution_address;
    let mut block_number = 1;

    let ecrecover_address = deploy_ecrecover(&mut debugger, sender, &mut block_number);

    let message = b"Hello, world";
    let mut personal_msg = ETH_PREFIX.to_vec();
    personal_msg.append(&mut message.to_vec());
    let personal_msg: &[u8] = personal_msg.as_ref();
    let hash = Hasher::digest(personal_msg);

    let mut rng = wild_rand::thread_rng();
    let private = Secp256k1RecoverablePrivateKey::generate(&mut rng);
    let sig = private
        .sign_message(&HashValue::from_bytes_unchecked(hash.0))
        .to_bytes();

    println!("sig: {}", hex_encode(sig.as_ref()));
    println!("private key: {}", hex_encode(private.to_bytes()));
    println!("hash: {}", hex_encode(&hash));

    let input = in_ecrecover::functions::in_ecrecover::encode_input(
        hash.0,
        sig[64],
        <[u8; 32]>::try_from(&sig[0..32]).unwrap(),
        <[u8; 32]>::try_from(&sig[32..64]).unwrap(),
    );

    println!("input: {}", hex_encode(&input));

    let tx = construct_tx(
        TransactionAction::Call(ecrecover_address),
        U256::default(),
        input,
    );
    let stx = mock_signed_tx(tx, sender);
    let resp = debugger.exec(block_number, vec![stx]);
    println!("return {:?}", resp);
    let addr = Hasher::digest(&private.pub_key().to_uncompressed_bytes().as_ref()[1..]);
    assert_eq!(resp.tx_resp[0].ret[12..], addr.0[12..]);
}
