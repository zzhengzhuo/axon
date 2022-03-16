use evm::{executor::stack::PrecompileFailure, ExitSucceed};
use sha2::Digest;

use super::linear_cost_precompile::LinearCostPrecompile;

pub struct Sha256;

impl LinearCostPrecompile for Sha256 {
    const BASE: u64 = 60;
    const WORD: u64 = 12;

    fn execute(input: &[u8], _cost: u64) -> Result<(ExitSucceed, Vec<u8>), PrecompileFailure> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(input);
        let ret = hasher.finalize();
        Ok((ExitSucceed::Returned, ret.to_vec()))
    }
}
