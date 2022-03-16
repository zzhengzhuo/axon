use evm::{
    executor::stack::{PrecompileFailure, PrecompileOutput, PrecompileSet},
    Context, ExitError, ExitSucceed,
};
use primitive_types::H160;

use self::{ecrecover::ECRecover, rsa::Rsa, sha256::Sha256};

pub(crate) mod ecrecover;
pub(crate) mod rsa;
pub(crate) mod sha256;

pub type PrecompileResult = Result<PrecompileOutput, PrecompileFailure>;
pub trait Precompile {
    /// Try to execute the precompile. Calculate the amount of gas needed with
    /// given `input` and `target_gas`. Return `Ok(status, output,
    /// gas_used)` if the execution is successful. Otherwise return
    /// `Err(_)`.
    fn execute(
        input: &[u8],
        target_gas: Option<u64>,
        context: &Context,
        is_static: bool,
    ) -> PrecompileResult;
}

pub mod linear_cost_precompile {
    use super::*;
    pub trait LinearCostPrecompile {
        const BASE: u64;
        const WORD: u64;

        fn execute(
            input: &[u8],
            cost: u64,
        ) -> core::result::Result<(ExitSucceed, Vec<u8>), PrecompileFailure>;
    }

    impl<T: LinearCostPrecompile> Precompile for T {
        fn execute(
            input: &[u8],
            target_gas: Option<u64>,
            _: &Context,
            _: bool,
        ) -> PrecompileResult {
            let cost = ensure_linear_cost(target_gas, input.len() as u64, T::BASE, T::WORD)?;

            let (exit_status, output) = T::execute(input, cost)?;
            Ok(PrecompileOutput {
                exit_status,
                cost,
                output,
                logs: Default::default(),
            })
        }
    }

    /// Linear gas cost
    fn ensure_linear_cost(
        target_gas: Option<u64>,
        len: u64,
        base: u64,
        word: u64,
    ) -> Result<u64, PrecompileFailure> {
        let cost = base
            .checked_add(word.checked_mul(len.saturating_add(31) / 32).ok_or(
                PrecompileFailure::Error {
                    exit_status: ExitError::OutOfGas,
                },
            )?)
            .ok_or(PrecompileFailure::Error {
                exit_status: ExitError::OutOfGas,
            })?;

        if let Some(target_gas) = target_gas {
            if cost > target_gas {
                return Err(PrecompileFailure::Error {
                    exit_status: ExitError::OutOfGas,
                });
            }
        }

        Ok(cost)
    }
}

fn hash(a: u64) -> H160 {
    H160::from_low_u64_be(a)
}

#[derive(Debug, Default)]
pub struct AxonPrecompiles;

impl AxonPrecompiles {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn used_address() -> Vec<H160> {
        vec![1, 2, 3, 4, 5, 1024, 1025]
            .into_iter()
            .map(|x| hash(x))
            .collect()
    }
}

impl PrecompileSet for AxonPrecompiles {
    fn is_precompile(&self, address: primitive_types::H160) -> bool {
        Self::used_address().contains(&address)
    }

    fn execute(
        &self,
        address: primitive_types::H160,
        input: &[u8],
        gas_limit: Option<u64>,
        context: &Context,
        is_static: bool,
    ) -> Option<PrecompileResult> {
        match address {
            // Ethereum precompiles :
            a if a == hash(1) => Some(ECRecover::execute(input, gas_limit, context, is_static)),
            a if a == hash(2) => Some(Sha256::execute(input, gas_limit, context, is_static)),
            a if a == hash(3) => todo!(),
            a if a == hash(4) => todo!(),
            a if a == hash(5) => todo!(),
            // Non-Frontier specific nor Ethereum precompiles :
            a if a == hash(1024) => {
                todo!()
            }
            a if a == hash(1025) => todo!(),
            a if a == hash(0xf4) => Some(Rsa::execute(input, gas_limit, context, is_static)),
            _ => None,
        }
    }
}
