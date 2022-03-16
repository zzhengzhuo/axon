use std::str::FromStr;

use evm::{ExitReason, ExitSucceed};
use primitive_types::{H160, U256};
use protocol::codec::hex_encode;
use protocol::tokio;
use protocol::{codec::hex_decode, types::TransactionAction};
use sha2::Digest;

use crate::debugger::{
    mock_signed_tx,
    uniswap2::{construct_tx, read_code},
    EvmDebugger,
};

ethabi_contract::use_contract!(in_sha256, "res/sha256.abi");

fn deploy_sha256(debugger: &mut EvmDebugger, sender: H160, block_number: &mut u64) -> H160 {
    println!("######## Deploy Sha256 contract");
    let code = hex_decode(&read_code("core/executor/res/sha256_code.txt")).unwrap();
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

    let ecrecover_address = deploy_sha256(&mut debugger, sender, &mut block_number);

    let message = b"Hello, world";

    let input = in_sha256::functions::in_sha256::encode_input(message.as_ref());

    println!("input: {}", hex_encode(&input));

    let tx = construct_tx(
        TransactionAction::Call(ecrecover_address),
        U256::default(),
        input,
    );
    let stx = mock_signed_tx(tx, sender);
    let resp = debugger.exec(block_number, vec![stx]);
    println!("return {:?}", resp);
    let mut hasher = sha2::Sha256::new();
    hasher.update(message);
    let ret = hasher.finalize();
    assert_eq!(&resp.tx_resp[0].ret, ret.as_slice());
}
