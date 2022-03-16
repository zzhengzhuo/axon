use evm::{executor::stack::PrecompileFailure, ExitError, ExitSucceed};
use rsa::{BigUint, PublicKey, RsaPublicKey};

use super::linear_cost_precompile::LinearCostPrecompile;

#[derive(Debug)]
pub struct Rsa;

impl LinearCostPrecompile for Rsa {
    const BASE: u64 = 3000;
    const WORD: u64 = 0;

    fn execute(i: &[u8], _: u64) -> Result<(ExitSucceed, Vec<u8>), PrecompileFailure> {
        let e = BigUint::from_bytes_be(&i[0..4]);
        let n_len =
            u32::from_be_bytes(i[4..8].try_into().map_err(|_| PrecompileFailure::Error {
                exit_status: ExitError::Other(std::borrow::Cow::Borrowed("e convert failed)")),
            })?) as usize;
        let n = BigUint::from_bytes_be(&i[8..8 + n_len]);
        let message_len = u32::from_be_bytes(i[8 + n_len..12 + n_len].try_into().map_err(|_| {
            PrecompileFailure::Error {
                exit_status: ExitError::Other(std::borrow::Cow::Borrowed("e convert failed)")),
            }
        })?) as usize;
        let message = &i[12 + n_len..12 + n_len + message_len];
        let sig_len = u32::from_be_bytes(
            i[12 + n_len + message_len..16 + n_len + message_len]
                .try_into()
                .map_err(|_| PrecompileFailure::Error {
                    exit_status: ExitError::Other(std::borrow::Cow::Borrowed("e convert failed)")),
                })?,
        ) as usize;
        let sig = &i[16 + n_len + message_len..16 + n_len + message_len + sig_len];

        let pubkey = RsaPublicKey::new(n, e).map_err(|e| PrecompileFailure::Error {
            exit_status: ExitError::Other(std::borrow::Cow::Owned(e.to_string())),
        })?;

        let result = match pubkey.verify(
            rsa::PaddingScheme::PKCS1v15Sign { hash: None },
            message,
            sig,
        ) {
            Ok(()) => vec![0u8; 32],
            Err(e) => {
                println!("error: {}", e);
                println!("pubkey: {:?}", pubkey);
                println!("message: {:?}", message);
                println!("sig: {:?}", sig);
                vec![1]
            }
        };
        Ok((ExitSucceed::Returned, result))
    }
}
