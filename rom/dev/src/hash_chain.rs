/*++

Licensed under the Apache-2.0 license.

File Name:

    hash_chain.rs

Abstract:

    File contains function to manage the firmware's hash chain.

--*/

#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_cfi_lib::cfi_assert_eq;
use caliptra_common::keyids::{KEY_ID_FW_HASH_CHAIN, KEY_ID_ROM_FMC_CDI};
use caliptra_drivers::{Hmac, HmacMode, KeyId, Trng};
use caliptra_error::CaliptraResult;

use crate::{crypto::Crypto, rom_env::RomEnv};

// This KeyId only holds the LDevID CDI during a specific phase of cold-boot: after
// the LDevID has been derived, but before firmware has been verified and executed.
const LDEVID_CDI: KeyId = KEY_ID_ROM_FMC_CDI;
const CHAIN_KEY: KeyId = KEY_ID_FW_HASH_CHAIN;

/// Initialize hash chain on cold reset.
///
/// # Arguments
///
/// * `env` - ROM Environment
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub(crate) fn initialize_hash_chain(
    env: &mut RomEnv,
    epoch: [u8; 2],
    chain_len: u32,
) -> CaliptraResult<()> {
    // Bind the chain to the following inputs.
    let chain_identity: [u8; 4] = [
        env.soc_ifc.lifecycle() as u8,
        env.soc_ifc.debug_locked() as u8,
        epoch[0],
        epoch[1],
    ];

    Crypto::env_hmac_kdf(
        env,
        LDEVID_CDI,
        b"hash_chain",
        Some(&chain_identity),
        CHAIN_KEY,
        HmacMode::Hmac512,
    )?;

    extend_hash_chain(&mut env.hmac, &mut env.trng, chain_len)
}

/// Extend hash chain, on cold or update reset.
///
/// # Arguments
///
/// * `env` - ROM Environment
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub(crate) fn extend_hash_chain(
    hmac: &mut Hmac,
    trng: &mut Trng,
    num_iters: u32,
) -> CaliptraResult<()> {
    let mut i: u32 = 0;

    for _ in 0..num_iters {
        i += 1;
        Crypto::hmac_kdf(
            hmac,
            trng,
            CHAIN_KEY,
            &[],
            None,
            CHAIN_KEY,
            HmacMode::Hmac512,
        )?;
    }

    cfi_assert_eq(num_iters, i);

    Ok(())
}