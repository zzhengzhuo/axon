use std::str::FromStr;

use ethabi::{ParamType, Token};
use evm::{ExitReason, ExitSucceed};
use num_traits::FromPrimitive;
use primitive_types::{H160, U256};
use protocol::codec::hex_encode;
use protocol::tokio;
use protocol::{codec::hex_decode, types::TransactionAction};
use rsa::{BigUint, Hash, PublicKey, RsaPublicKey};
use sha2::{Digest, Sha256};

use crate::debugger::{
    mock_signed_tx,
    uniswap2::{construct_tx, read_code},
    EvmDebugger,
};
use crate::precompile::email_parse::email_from_hash;

ethabi_contract::use_contract!(in_dkim, "res/dkim.abi");

fn deploy_dkim(debugger: &mut EvmDebugger, sender: H160, block_number: &mut u64) -> H160 {
    println!("######## Deploy Dkim contract");
    let code = hex_decode(&read_code("core/executor/res/dkim_code.txt")).unwrap();
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
async fn test_dkim() {
    println!("current dir: {:?}", std::env::current_dir());
    let distribution_address =
        H160::from_str("0x3f17f1962b36e491b30a40b2405849e597ba5fb5").unwrap();
    let distribution_amount: U256 = 1234560000000000000000000u128.into();
    let db_path = "core/executor/free-space/db0";

    let mut debugger = EvmDebugger::new(distribution_address, distribution_amount, db_path);
    let sender = distribution_address;
    let mut block_number = 1;

    let ecrecover_address = deploy_dkim(&mut debugger, sender, &mut block_number);

    let eml = read_code("core/executor/res/qq.eml");

    let n = hex_decode("cfb0520e4ad78c4adb0deb5e605162b6469349fc1fde9269b88d596ed9f3735c00c592317c982320874b987bcc38e8556ac544bdee169b66ae8fe639828ff5afb4f199017e3d8e675a077f21cd9e5c526c1866476e7ba74cd7bb16a1c3d93bc7bb1d576aedb4307c6b948d5b8c29f79307788d7a8ebf84585bf53994827c23a5").unwrap();
    let n = BigUint::from_bytes_be(&n);
    let e = BigUint::from_u32(65537).unwrap();
    let public_key = RsaPublicKey::new(n, e).unwrap();

    let input = in_dkim::functions::validate::encode_input(eml);

    let tx = construct_tx(
        TransactionAction::Call(ecrecover_address),
        U256::default(),
        input,
    );
    let stx = mock_signed_tx(tx, sender);
    let resp = debugger.exec(block_number, vec![stx]);

    println!("return {:?}", resp);

    let ret = ethabi::decode(
        &[
            ParamType::FixedBytes(32),
            ParamType::FixedBytes(32),
            ParamType::FixedBytes(32),
            ParamType::FixedBytes(32),
            ParamType::Bytes,
            ParamType::Bytes,
        ],
        &resp.tx_resp[0].ret,
    )
    .unwrap();

    if let (
        Token::FixedBytes(from),
        Token::FixedBytes(subject),
        Token::FixedBytes(selector),
        Token::FixedBytes(sdid),
        Token::Bytes(message),
        Token::Bytes(sig),
    ) = (&ret[0], &ret[1], &ret[2], &ret[3], &ret[4], &ret[5])
    {
        assert_eq!(
            hex_encode(subject),
            "531d170d86ec42bfe007c09f7e232f3870af3184eb2061fd9d406b3143d7c097"
        );
        assert_eq!(&selector[..7], b"s201512");
        assert_eq!(&sdid[..6], b"qq.com");

        let mut email_from = "517669936@qq.com".to_owned();
        let from_hash = email_from_hash(&mut email_from).unwrap();
        assert_eq!(from, from_hash.as_slice());
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message = hasher.finalize();
        assert!(public_key
            .verify(
                rsa::PaddingScheme::PKCS1v15Sign {
                    hash: Some(Hash::SHA2_256),
                },
                &message,
                sig,
            )
            .is_ok());
    } else {
        panic!("invalid output");
    }
}
