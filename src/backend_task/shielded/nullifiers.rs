use crate::backend_task::error::TaskError;
use crate::context::AppContext;
use crate::model::wallet::WalletSeedHash;
use crate::model::wallet::shielded::ShieldedWalletState;
use dash_sdk::dpp::dashcore::Network;
use dash_sdk::platform::shielded::nullifier_sync::{NullifierSyncCheckpoint, NullifierSyncConfig};
use std::collections::BTreeSet;
use std::sync::Arc;

/// Check which unspent notes have been spent on-chain using the SDK's
/// privacy-preserving nullifier sync.
///
/// The SDK handles full tree scan vs incremental catch-up internally based
/// on the provided `last_sync_height` and `last_sync_timestamp`.
pub async fn check_nullifiers(
    app_context: &Arc<AppContext>,
    seed_hash: &WalletSeedHash,
    shielded_state: &mut ShieldedWalletState,
    network: Network,
) -> Result<u32, TaskError> {
    let sdk = { app_context.sdk.load().as_ref().clone() };

    let network_str = network.to_string();

    // Collect unspent nullifier bytes for the provider
    let unspent_nullifiers: Vec<[u8; 32]> = shielded_state
        .notes
        .iter()
        .filter(|n| !n.is_spent)
        .map(|n| n.nullifier.to_bytes())
        .collect();

    if unspent_nullifiers.is_empty() {
        return Ok(0);
    }

    let last_height = shielded_state.last_nullifier_sync_height;
    let last_timestamp = shielded_state.last_nullifier_sync_timestamp;

    let last_sync = if last_height > 0 || last_timestamp > 0 {
        Some(NullifierSyncCheckpoint {
            height: last_height,
            timestamp: last_timestamp,
        })
    } else {
        None
    };

    let result = sdk
        .sync_nullifiers(&unspent_nullifiers, None::<NullifierSyncConfig>, last_sync)
        .await
        .map_err(|e| TaskError::ShieldedNullifierSyncFailed {
            detail: e.to_string(),
        })?;

    let mut matched_note_indexes = BTreeSet::new();
    for nf_bytes in &result.found {
        if let Some((idx, _)) = shielded_state
            .notes
            .iter()
            .enumerate()
            .find(|(_, note)| !note.is_spent && note.nullifier.to_bytes() == *nf_bytes)
        {
            matched_note_indexes.insert(idx);
        }
    }

    for nf_bytes in &result.found {
        app_context
            .db
            .mark_shielded_note_spent(seed_hash, nf_bytes, &network_str)?;
    }

    app_context
        .db
        .set_nullifier_sync_info(
            seed_hash,
            &network_str,
            result.new_sync_height,
            result.new_sync_timestamp,
        )
        .map_err(|detail| TaskError::ShieldedNullifierSyncFailed { detail })?;

    let spent_count = matched_note_indexes.len() as u32;
    for idx in matched_note_indexes {
        if let Some(note) = shielded_state.notes.get_mut(idx) {
            note.is_spent = true;
        }
    }
    shielded_state.last_nullifier_sync_height = result.new_sync_height;
    shielded_state.last_nullifier_sync_timestamp = result.new_sync_timestamp;

    if spent_count > 0 {
        shielded_state.recalculate_balance();
    }

    Ok(spent_count)
}
