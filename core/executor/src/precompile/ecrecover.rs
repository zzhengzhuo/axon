use std::cmp::min;

use common_crypto::secp256k1_recover;
use evm::{executor::stack::PrecompileFailure, ExitSucceed};
use protocol::types::Hasher;

use super::linear_cost_precompile::LinearCostPrecompile;

#[derive(Debug)]
pub struct ECRecover;

impl LinearCostPrecompile for ECRecover {
    const BASE: u64 = 3000;
    const WORD: u64 = 0;

    fn execute(i: &[u8], _: u64) -> Result<(ExitSucceed, Vec<u8>), PrecompileFailure> {
        let mut input = [0u8; 128];
        input[..min(i.len(), 128)].copy_from_slice(&i[..min(i.len(), 128)]);

        let mut msg = [0u8; 32];
        let mut sig = [0u8; 65];

        msg[0..32].copy_from_slice(&input[0..32]);
        sig[0..32].copy_from_slice(&input[64..96]);
        sig[32..64].copy_from_slice(&input[96..128]);
        sig[64] = input[63];

        let result = match secp256k1_recover(&msg, &sig) {
            Ok(pubkey) => {
                let mut address = Hasher::digest(&pubkey.serialize_uncompressed()[1..]).0;
                address[0..12].copy_from_slice(&[0u8; 12]);
                address.to_vec()
            }
            Err(e) => {
                println!("error: {}", e);
                [0u8; 0].to_vec()
            }
        };

        Ok((ExitSucceed::Returned, result))
    }
}
