use std::borrow::Cow;

use email_rs::{Email, Header};
use evm::{executor::stack::PrecompileFailure, ExitError, ExitSucceed};
use protocol::codec::hex_decode;
use sha2::{Digest, Sha256};

use super::linear_cost_precompile::LinearCostPrecompile;

pub const MIN_EMAIL_LEN: usize = 6;
pub const MAX_EMAIL_LEN: usize = 100;
pub const FR_EMAIL_LEN: usize = MAX_EMAIL_LEN / 31 + 1;

#[derive(Debug)]
pub struct EmailParse;

impl LinearCostPrecompile for EmailParse {
    const BASE: u64 = 3000;
    const WORD: u64 = 0;

    fn execute(i: &[u8], _: u64) -> Result<(ExitSucceed, Vec<u8>), PrecompileFailure> {
        let s = String::from_utf8_lossy(i);
        let email = Email::from_str(&s).map_err(|_| PrecompileFailure::Error {
            exit_status: ExitError::Other(std::borrow::Cow::Borrowed("email parse failed")),
        })?;

        let subject = email
            .get_header_value("subject")
            .map_err(|_| PrecompileFailure::Error {
                exit_status: ExitError::Other(std::borrow::Cow::Borrowed(
                    "get email subject failed",
                )),
            })?;
        let subject = subject
            .split("0x")
            .enumerate()
            .find(|(i, _)| *i == 1)
            .ok_or(PrecompileFailure::Error {
                exit_status: ExitError::Other(std::borrow::Cow::Borrowed(
                    "get email subject header failed",
                )),
            })?
            .1;
        let subject = hex_decode(&subject).map_err(|_| PrecompileFailure::Error {
            exit_status: ExitError::Other(std::borrow::Cow::Borrowed("invalid subject")),
        })?;

        if subject.len() != 32 {
            return Err(PrecompileFailure::Error {
                exit_status: ExitError::Other(std::borrow::Cow::Borrowed("invalid email subject")),
            });
        }

        let from = email
            .get_header_item("from")
            .map_err(|_| PrecompileFailure::Error {
                exit_status: ExitError::Other(std::borrow::Cow::Borrowed(
                    "get email from header failed",
                )),
            })?;
        let mut email_from =
            Email::extract_address_of_from(from).map_err(|_| PrecompileFailure::Error {
                exit_status: ExitError::Other(std::borrow::Cow::Borrowed(
                    "get email from header failed",
                )),
            })?;

        let from = email_from_hash(&mut email_from).map_err(|e| PrecompileFailure::Error {
            exit_status: ExitError::Other(std::borrow::Cow::Owned(e.to_string())),
        })?;

        let dkim_message = &email.get_dkim_message()[0];

        let Header {
            selector,
            sdid,
            signature,
            ..
        } = &email.dkim_headers[0];

        if selector.len() > 32 || sdid.len() > 32 {
            return Err(PrecompileFailure::Error {
                exit_status: ExitError::Other(std::borrow::Cow::Borrowed(
                    "get email subject failed",
                )),
            });
        }

        let dkim_message_len_ceil = (dkim_message.len() / 32 + 1) * 32;
        let signature_len_ceil = signature.len();
        let mut result = vec![0u8; 32 * 8 + dkim_message_len_ceil + signature_len_ceil];
        result[0..32].copy_from_slice(&from);
        result[32..64].copy_from_slice(&subject[..32]);
        result[64..64 + selector.len()].copy_from_slice(selector.as_bytes());
        result[96..96 + sdid.len()].copy_from_slice(sdid.as_bytes());
        result[159] = 0xc0;
        result[188..192].copy_from_slice(&((0xe0 + dkim_message_len_ceil) as u32).to_be_bytes());
        result[220..224].copy_from_slice(&(dkim_message.len() as u32).to_be_bytes());
        result[224..224 + dkim_message.len()].copy_from_slice(dkim_message.as_bytes());
        result[252 + dkim_message_len_ceil..256 + dkim_message_len_ceil]
            .copy_from_slice(&(signature.len() as u32).to_be_bytes());
        result[256 + dkim_message_len_ceil..256 + dkim_message_len_ceil + signature.len()]
            .copy_from_slice(signature);

        Ok((ExitSucceed::Returned, result))
    }
}

pub(crate) fn email_from_hash(email_from: &mut str) -> anyhow::Result<[u8; 32]> {
    email_from.make_ascii_lowercase();
    let email_split: Vec<&str> = email_from.split('@').collect();
    let mut local_part = Cow::Borrowed(email_split[0]);
    let domain = email_split[1];
    if email_split[1] == "gmail.com" {
        local_part = local_part.chars().filter(|c| c != &'.').collect();
    }
    let len = local_part.len() + domain.len() + 1;
    if len > MAX_EMAIL_LEN || len < MIN_EMAIL_LEN {
        return Err(anyhow::anyhow!(
            "invalid email from len,should between {} and {}",
            MIN_EMAIL_LEN,
            MAX_EMAIL_LEN
        ));
    }
    let mut hash = Sha256::new();
    hash.update(local_part.as_bytes());
    hash.update([b'@']);
    hash.update(domain);
    hash.update(&vec![0u8; FR_EMAIL_LEN * 31 - len]);
    let mut hash_res = hash.finalize().to_vec();
    hash_res.reverse();
    hash_res[31] &= 0x1f;
    hash_res
        .try_into()
        .map_err(|_| anyhow::anyhow!("hash convert failed"))
}
