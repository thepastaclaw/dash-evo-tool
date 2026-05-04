use super::BackendTaskSuccessResult;
use crate::backend_task::FeeResult;
use crate::backend_task::error::TaskError;
use crate::context::AppContext;
use crate::model::fee_estimation::PlatformFeeEstimator;
use crate::model::qualified_identity::QualifiedIdentity;
use dash_sdk::Error as SdkError;
use dash_sdk::Sdk;
use dash_sdk::dpp::identity::Identity;
use dash_sdk::dpp::identity::accessors::{IdentityGettersV0, IdentitySettersV0};
use dash_sdk::dpp::identity::identity_public_key::accessors::v0::IdentityPublicKeyGettersV0;
use dash_sdk::dpp::identity::{KeyID, Purpose, SecurityLevel};
use dash_sdk::dpp::prelude::UserFeeIncrease;
use dash_sdk::dpp::state_transition::identity_update_transition::IdentityUpdateTransition;
use dash_sdk::dpp::state_transition::identity_update_transition::methods::IdentityUpdateTransitionMethodsV0;
use dash_sdk::dpp::state_transition::proof_result::StateTransitionProofResult;
use dash_sdk::platform::Fetch;
use dash_sdk::platform::transition::broadcast::BroadcastStateTransition;

/// Render a [`SecurityLevel`] as a stable, human-readable string. Used in user-facing
/// errors so the wording stays the same regardless of `Debug` formatting changes.
pub fn security_level_label(level: SecurityLevel) -> &'static str {
    match level {
        SecurityLevel::MASTER => "Master",
        SecurityLevel::CRITICAL => "Critical",
        SecurityLevel::HIGH => "High",
        SecurityLevel::MEDIUM => "Medium",
    }
}

/// Render a [`Purpose`] as a stable, human-readable string. Used in user-facing
/// errors and dialog labels.
pub fn purpose_label(purpose: Purpose) -> &'static str {
    match purpose {
        Purpose::AUTHENTICATION => "Authentication",
        Purpose::ENCRYPTION => "Encryption",
        Purpose::DECRYPTION => "Decryption",
        Purpose::TRANSFER => "Transfer",
        Purpose::SYSTEM => "System",
        Purpose::VOTING => "Voting",
        Purpose::OWNER => "Owner",
    }
}

/// Validate that the given `key_ids` can be safely disabled on `identity`.
///
/// Rules enforced (defense-in-depth — UI also pre-checks before allowing the action):
/// - the set is non-empty,
/// - every key id is present on the identity,
/// - no listed key is already disabled,
/// - no listed key is the MASTER key (read-only on Platform),
/// - for each non-master key being disabled, at least one other enabled key with the
///   same `(purpose, security_level)` must remain after the batch is applied —
///   otherwise the identity would lose its only key for that role and could no longer
///   authenticate, transfer, vote, or otherwise act in that capacity.
pub fn validate_keys_can_be_disabled(
    identity: &Identity,
    key_ids: &[KeyID],
) -> Result<(), TaskError> {
    if key_ids.is_empty() {
        return Err(TaskError::NoKeysToDisable);
    }

    let public_keys = identity.public_keys();

    for key_id in key_ids {
        let key = public_keys
            .get(key_id)
            .ok_or(TaskError::KeyNotFoundOnIdentity { key_id: *key_id })?;

        if key.is_disabled() {
            return Err(TaskError::KeyAlreadyDisabled { key_id: *key_id });
        }

        if key.security_level() == SecurityLevel::MASTER {
            return Err(TaskError::CannotDisableMasterKey { key_id: *key_id });
        }

        let purpose = key.purpose();
        let level = key.security_level();
        // At least one enabled key with the same (purpose, security level) must remain
        // after the batch is applied. `key_ids.contains(&k.id())` already excludes the
        // current `key_id` since it is in the batch.
        let still_enabled = public_keys.values().any(|k| {
            !k.is_disabled()
                && k.purpose() == purpose
                && k.security_level() == level
                && !key_ids.contains(&k.id())
        });
        if !still_enabled {
            return Err(TaskError::WouldLeaveNoKeyAtPurposeLevel {
                key_id: *key_id,
                purpose: purpose_label(purpose),
                security_level: security_level_label(level),
            });
        }
    }

    Ok(())
}

impl AppContext {
    pub(super) async fn disable_identity_keys(
        &self,
        sdk: &Sdk,
        mut qualified_identity: QualifiedIdentity,
        key_ids_to_disable: Vec<KeyID>,
    ) -> Result<BackendTaskSuccessResult, TaskError> {
        if key_ids_to_disable.is_empty() {
            return Err(TaskError::NoKeysToDisable);
        }

        // Fetch fresh identity so validation runs against current Platform state.
        let identity = Identity::fetch_by_identifier(sdk, qualified_identity.identity.id())
            .await?
            .ok_or(TaskError::IdentityNotFoundOnPlatform)?;
        qualified_identity.identity = identity;

        validate_keys_can_be_disabled(&qualified_identity.identity, &key_ids_to_disable)?;

        let Some(master_key) = qualified_identity.can_sign_with_master_key() else {
            return Err(TaskError::MasterKeyNotFound);
        };
        let master_key_id = master_key.identity_public_key.id();

        let new_identity_nonce = sdk
            .get_identity_nonce(qualified_identity.identity.id(), true, None)
            .await?;

        qualified_identity.identity.bump_revision();

        let balance_before = qualified_identity.identity.balance();
        let estimated_fee = PlatformFeeEstimator::new().estimate_identity_update();

        let state_transition = IdentityUpdateTransition::try_from_identity_with_signer(
            &qualified_identity.identity,
            &master_key_id,
            vec![],
            key_ids_to_disable.clone(),
            new_identity_nonce,
            UserFeeIncrease::default(),
            &qualified_identity,
            sdk.version(),
            None,
        )
        .map_err(|e| TaskError::IdentityUpdateTransitionError {
            source_error: Box::new(SdkError::Protocol(e)),
        })?;

        let result = state_transition.broadcast_and_wait(sdk, None).await?;
        tracing::info!(
            identity_id = %qualified_identity.identity.id(),
            ?key_ids_to_disable,
            "DisableIdentityKeys proof result: {}",
            result
        );

        // Only the proof-verified path updates local key state. Other proof shapes are
        // logged so a subsequent refresh reconciles against canonical Platform state —
        // we deliberately do not fabricate a `disabled_at` timestamp.
        let new_balance = match result {
            StateTransitionProofResult::VerifiedPartialIdentity(partial_identity) => {
                let balance = partial_identity.balance;
                // Insert/overwrite the keys returned by the proof — these now carry
                // the platform-assigned `disabled_at` timestamp on the disabled keys.
                for public_key in partial_identity.loaded_public_keys.into_values() {
                    qualified_identity.identity.add_public_key(public_key);
                }
                balance
            }
            other => {
                tracing::warn!(
                    identity_id = %qualified_identity.identity.id(),
                    ?key_ids_to_disable,
                    "Unexpected proof result type for disable identity keys: {}; local key state will be reconciled on next refresh",
                    other
                );
                None
            }
        };

        let actual_fee = if let Some(balance_after) = new_balance {
            let fee = balance_before.saturating_sub(balance_after);
            tracing::info!(
                "DisableIdentityKeys complete: estimated fee {} credits, actual fee {} credits",
                estimated_fee,
                fee
            );
            qualified_identity.identity.set_balance(balance_after);
            fee
        } else {
            estimated_fee
        };

        let fee_result = FeeResult::new(estimated_fee, actual_fee);

        self.update_local_qualified_identity(&qualified_identity)
            .map_err(|e| TaskError::Database { source: e })?;

        Ok(BackendTaskSuccessResult::DisabledIdentityKeys {
            identity: qualified_identity,
            disabled_key_ids: key_ids_to_disable,
            fee_result,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dash_sdk::dpp::identity::identity_public_key::v0::IdentityPublicKeyV0;
    use dash_sdk::dpp::identity::{KeyType, Purpose, SecurityLevel};
    use dash_sdk::dpp::prelude::Identifier;
    use dash_sdk::platform::IdentityPublicKey;

    fn make_key(
        id: KeyID,
        purpose: Purpose,
        level: SecurityLevel,
        disabled: bool,
    ) -> IdentityPublicKey {
        IdentityPublicKey::V0(IdentityPublicKeyV0 {
            id,
            purpose,
            security_level: level,
            contract_bounds: None,
            key_type: KeyType::ECDSA_HASH160,
            read_only: false,
            // Public-key data is not inspected by the validator; just needs to be the right
            // size for ECDSA_HASH160 (20 bytes).
            data: vec![0u8; 20].into(),
            disabled_at: if disabled { Some(1) } else { None },
        })
    }

    fn make_identity(keys: Vec<IdentityPublicKey>) -> Identity {
        let mut identity = Identity::create_basic_identity(
            Identifier::from([0u8; 32]),
            dash_sdk::dpp::version::PlatformVersion::latest(),
        )
        .expect("create basic identity");
        for key in keys {
            identity.add_public_key(key);
        }
        identity
    }

    #[test]
    fn empty_key_set_rejected() {
        let identity = make_identity(vec![make_key(
            0,
            Purpose::AUTHENTICATION,
            SecurityLevel::MASTER,
            false,
        )]);
        let err = validate_keys_can_be_disabled(&identity, &[]).unwrap_err();
        assert!(matches!(err, TaskError::NoKeysToDisable));
    }

    #[test]
    fn unknown_key_id_rejected() {
        let identity = make_identity(vec![make_key(
            0,
            Purpose::AUTHENTICATION,
            SecurityLevel::MASTER,
            false,
        )]);
        let err = validate_keys_can_be_disabled(&identity, &[42]).unwrap_err();
        assert!(matches!(
            err,
            TaskError::KeyNotFoundOnIdentity { key_id: 42 }
        ));
    }

    #[test]
    fn already_disabled_key_rejected() {
        let identity = make_identity(vec![
            make_key(0, Purpose::AUTHENTICATION, SecurityLevel::MASTER, false),
            make_key(1, Purpose::AUTHENTICATION, SecurityLevel::HIGH, true),
        ]);
        let err = validate_keys_can_be_disabled(&identity, &[1]).unwrap_err();
        assert!(matches!(err, TaskError::KeyAlreadyDisabled { key_id: 1 }));
    }

    #[test]
    fn master_key_cannot_be_disabled() {
        let identity = make_identity(vec![make_key(
            0,
            Purpose::AUTHENTICATION,
            SecurityLevel::MASTER,
            false,
        )]);
        let err = validate_keys_can_be_disabled(&identity, &[0]).unwrap_err();
        assert!(matches!(
            err,
            TaskError::CannotDisableMasterKey { key_id: 0 }
        ));
    }

    #[test]
    fn rejects_disabling_only_authentication_key_at_level() {
        // One CRITICAL auth key, one HIGH auth key, master. Disabling the HIGH auth key
        // would leave no enabled HIGH-level authentication key.
        let identity = make_identity(vec![
            make_key(0, Purpose::AUTHENTICATION, SecurityLevel::MASTER, false),
            make_key(1, Purpose::AUTHENTICATION, SecurityLevel::CRITICAL, false),
            make_key(2, Purpose::AUTHENTICATION, SecurityLevel::HIGH, false),
        ]);
        let err = validate_keys_can_be_disabled(&identity, &[2]).unwrap_err();
        assert!(matches!(
            err,
            TaskError::WouldLeaveNoKeyAtPurposeLevel {
                key_id: 2,
                purpose: "Authentication",
                security_level: "High",
            }
        ));
    }

    #[test]
    fn allows_disabling_when_other_auth_key_at_same_level_remains() {
        let identity = make_identity(vec![
            make_key(0, Purpose::AUTHENTICATION, SecurityLevel::MASTER, false),
            make_key(1, Purpose::AUTHENTICATION, SecurityLevel::CRITICAL, false),
            make_key(2, Purpose::AUTHENTICATION, SecurityLevel::HIGH, false),
            make_key(3, Purpose::AUTHENTICATION, SecurityLevel::HIGH, false),
        ]);
        validate_keys_can_be_disabled(&identity, &[2]).expect("should be allowed");
    }

    #[test]
    fn rejects_batch_that_drains_a_level_even_if_other_remains_in_batch() {
        // Both HIGH auth keys are in the disable batch — none remain enabled at HIGH.
        let identity = make_identity(vec![
            make_key(0, Purpose::AUTHENTICATION, SecurityLevel::MASTER, false),
            make_key(1, Purpose::AUTHENTICATION, SecurityLevel::CRITICAL, false),
            make_key(2, Purpose::AUTHENTICATION, SecurityLevel::HIGH, false),
            make_key(3, Purpose::AUTHENTICATION, SecurityLevel::HIGH, false),
        ]);
        let err = validate_keys_can_be_disabled(&identity, &[2, 3]).unwrap_err();
        assert!(matches!(
            err,
            TaskError::WouldLeaveNoKeyAtPurposeLevel { .. }
        ));
    }

    #[test]
    fn rejects_disabling_only_transfer_key() {
        // The bricking-protection rule applies to all non-master purposes — disabling
        // the only TRANSFER key would leave the identity unable to withdraw or transfer.
        let identity = make_identity(vec![
            make_key(0, Purpose::AUTHENTICATION, SecurityLevel::MASTER, false),
            make_key(1, Purpose::AUTHENTICATION, SecurityLevel::CRITICAL, false),
            make_key(2, Purpose::TRANSFER, SecurityLevel::CRITICAL, false),
        ]);
        let err = validate_keys_can_be_disabled(&identity, &[2]).unwrap_err();
        assert!(matches!(
            err,
            TaskError::WouldLeaveNoKeyAtPurposeLevel {
                key_id: 2,
                purpose: "Transfer",
                ..
            }
        ));
    }

    #[test]
    fn allows_disabling_transfer_key_with_replacement() {
        let identity = make_identity(vec![
            make_key(0, Purpose::AUTHENTICATION, SecurityLevel::MASTER, false),
            make_key(1, Purpose::AUTHENTICATION, SecurityLevel::CRITICAL, false),
            make_key(2, Purpose::TRANSFER, SecurityLevel::CRITICAL, false),
            make_key(3, Purpose::TRANSFER, SecurityLevel::CRITICAL, false),
        ]);
        validate_keys_can_be_disabled(&identity, &[2])
            .expect("transfer key should be disable-able when a replacement exists");
    }

    #[test]
    fn master_check_wins_over_no_replacement_check() {
        // The master key has no replacement at MASTER level — confirm the validator
        // returns CannotDisableMasterKey rather than the bricking variant.
        let identity = make_identity(vec![
            make_key(0, Purpose::AUTHENTICATION, SecurityLevel::MASTER, false),
            make_key(1, Purpose::AUTHENTICATION, SecurityLevel::CRITICAL, false),
        ]);
        let err = validate_keys_can_be_disabled(&identity, &[0]).unwrap_err();
        assert!(matches!(
            err,
            TaskError::CannotDisableMasterKey { key_id: 0 }
        ));
    }

    #[test]
    fn batch_with_unknown_id_reports_not_found() {
        // The validator iterates in order. With a valid+replaceable id followed by an
        // unknown id, the unknown id should surface as KeyNotFoundOnIdentity.
        let identity = make_identity(vec![
            make_key(0, Purpose::AUTHENTICATION, SecurityLevel::MASTER, false),
            make_key(1, Purpose::AUTHENTICATION, SecurityLevel::CRITICAL, false),
            make_key(2, Purpose::AUTHENTICATION, SecurityLevel::CRITICAL, false),
        ]);
        let err = validate_keys_can_be_disabled(&identity, &[1, 99]).unwrap_err();
        assert!(matches!(
            err,
            TaskError::KeyNotFoundOnIdentity { key_id: 99 }
        ));
    }

    #[test]
    fn batch_with_master_and_non_master_rejects_master() {
        // Mixed batch: the master id is processed in order; once reached the master
        // check should fire regardless of the other entries.
        let identity = make_identity(vec![
            make_key(0, Purpose::AUTHENTICATION, SecurityLevel::MASTER, false),
            make_key(1, Purpose::AUTHENTICATION, SecurityLevel::CRITICAL, false),
            make_key(2, Purpose::AUTHENTICATION, SecurityLevel::CRITICAL, false),
        ]);
        let err = validate_keys_can_be_disabled(&identity, &[1, 0]).unwrap_err();
        assert!(matches!(
            err,
            TaskError::CannotDisableMasterKey { key_id: 0 }
        ));
    }
}
