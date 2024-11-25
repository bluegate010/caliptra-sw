/*++

Licensed under the Apache-2.0 license.

File Name:

    hash_chain.rs

Abstract:

    File contains hash chain utilities.

--*/

use crate::{handoff::RtHandoff, Drivers, Hmac};
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::keyids::KEY_ID_TMP;
use caliptra_drivers::{CaliptraResult, HmacMode, KeyId};
use caliptra_error::CaliptraError;

pub struct HashChain;
impl HashChain {
    /// Calculates a secret from the hash chain.
    ///
    /// Extends the hash chain the requisite number of times, based on
    /// the given target SVN. Fails if the target SVN is too large. Runs
    /// a final KDF to derive the resulting secret in the destination KV
    /// slot.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub fn derive_secret(
        drivers: &mut Drivers,
        target_svn: u32,
        context: &[u8],
        dest: KeyId,
    ) -> CaliptraResult<()> {
        let handoff = RtHandoff {
            data_vault: &drivers.persistent_data.get().data_vault,
            fht: &drivers.persistent_data.get().fht,
        };

        let hash_chain_svn = handoff.rt_min_svn();
        let hash_chain_kv = handoff.rt_hash_chain()?;

        // Don't allow stomping over the hash chain secret.
        if dest == hash_chain_kv {
            // If this occurs it is an internal programming error within Caliptra firmware.
            Err(CaliptraError::RUNTIME_INTERNAL)?;
        }

        if target_svn > hash_chain_svn {
            Err(CaliptraError::RUNTIME_HASH_CHAIN_TARGET_SVN_TOO_LARGE)?;
        }

        let num_iters = hash_chain_svn - target_svn;

        let mut extend_chain = |key_in: KeyId, key_out: KeyId| {
            Hmac::hmac_kdf(drivers, key_in, &[], None, HmacMode::Hmac512, key_out)
        };

        let kdf_source = if num_iters == 0 {
            hash_chain_kv
        } else {
            extend_chain(hash_chain_kv, KEY_ID_TMP)?;
            for _ in 1..num_iters {
                extend_chain(KEY_ID_TMP, KEY_ID_TMP)?;
            }
            KEY_ID_TMP
        };

        Hmac::hmac_kdf(
            drivers,
            kdf_source,
            b"chain_output",
            Some(context),
            HmacMode::Hmac512,
            dest,
        )?;

        if kdf_source == KEY_ID_TMP && dest != KEY_ID_TMP {
            drivers.key_vault.erase_key(KEY_ID_TMP).unwrap();
        }

        Ok(())
    }
}
