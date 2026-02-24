use crate::backend_task::BackendTaskSuccessResult;
use crate::context::AppContext;
use crate::model::proof_log_item::{ProofLogItem, RequestType};
use crate::model::qualified_identity::QualifiedIdentity;
use dash_sdk::dpp::data_contract::accessors::v1::DataContractV1Getters;
use dash_sdk::dpp::data_contract::associated_token::token_distribution_key::TokenDistributionType;
use dash_sdk::dpp::document::DocumentV0Getters;
use dash_sdk::dpp::identity::accessors::IdentityGettersV0;
use dash_sdk::dpp::platform_value::Value;
use dash_sdk::dpp::state_transition::proof_result::StateTransitionProofResult;
use dash_sdk::platform::tokens::builders::claim::TokenClaimTransitionBuilder;
use dash_sdk::platform::tokens::transitions::ClaimResult;
use dash_sdk::platform::transition::broadcast::BroadcastStateTransition;
use dash_sdk::platform::{DataContract, Identifier, IdentityPublicKey};
use dash_sdk::{Error, Sdk};
use std::sync::Arc;

impl AppContext {
    #[allow(clippy::too_many_arguments)]
    pub async fn claim_tokens(
        &self,
        data_contract: Arc<DataContract>,
        token_position: u16,
        actor_identity: &QualifiedIdentity,
        distribution_type: TokenDistributionType,
        signing_key: IdentityPublicKey,
        public_note: Option<String>,
        sdk: &Sdk,
    ) -> Result<BackendTaskSuccessResult, String> {
        // Build
        let mut builder = TokenClaimTransitionBuilder::new(
            data_contract.clone(),
            token_position,
            actor_identity.identity.id(),
            distribution_type,
        );

        if let Some(note) = public_note {
            builder = builder.with_public_note(note);
        }

        let maybe_options = self.state_transition_options();
        if let Some(options) = maybe_options {
            builder = builder.with_state_transition_creation_options(options);
        }

        let put_settings = builder.settings;
        let state_transition = builder
            .sign(sdk, &signing_key, actor_identity, sdk.version())
            .await
            .map_err(|e| self.map_claim_broadcast_error_for_ui(e))?;

        let proof_result = match state_transition.broadcast(sdk, put_settings).await {
            Ok(()) => state_transition
                .wait_for_response::<StateTransitionProofResult>(sdk, put_settings)
                .await,
            Err(e) if is_tx_already_exists_in_cache_error(&e) => {
                tracing::warn!(
                    "ClaimTokens transition already in mempool cache; waiting for existing transition result"
                );
                state_transition
                    .wait_for_response::<StateTransitionProofResult>(sdk, put_settings)
                    .await
            }
            Err(e) => Err(e),
        }
        .map_err(|e| self.map_claim_broadcast_error_for_ui(e))?;

        let result = match proof_result {
            StateTransitionProofResult::VerifiedTokenActionWithDocument(document) => {
                ClaimResult::Document(document)
            }
            StateTransitionProofResult::VerifiedTokenGroupActionWithDocument(
                power,
                Some(document),
            ) => ClaimResult::GroupActionWithDocument(power, document),
            StateTransitionProofResult::VerifiedTokenGroupActionWithDocument(_, None) => {
                return Err(
                    "Error broadcasting ClaimTokens transition: Expected document in group action result"
                        .to_string(),
                );
            }
            _ => {
                return Err(
                    "Error broadcasting ClaimTokens transition: Expected VerifiedTokenActionWithDocument or VerifiedTokenGroupActionWithDocument for claim transition"
                        .to_string(),
                );
            }
        };

        // Using the result, update the balance of the claimer identity
        if let Some(token_id) = data_contract.token_id(token_position) {
            match result {
                // Standard claim result - extract claimer and amount from document
                ClaimResult::Document(document) => {
                    if let (Some(claimer_value), Some(amount_value)) =
                        (document.get("claimerId"), document.get("amount"))
                        && let (Value::Identifier(claimer_bytes), Value::U64(amount)) =
                            (claimer_value, amount_value)
                        && let Ok(claimer_id) = Identifier::from_bytes(claimer_bytes)
                        && let Err(e) =
                            self.insert_token_identity_balance(&token_id, &claimer_id, *amount)
                    {
                        tracing::error!(
                            "Failed to update token balance from claim document: {}",
                            e
                        );
                    }
                }

                // Group action with document - assume completed if document exists
                ClaimResult::GroupActionWithDocument(_, document) => {
                    if let (Some(claimer_value), Some(amount_value)) =
                        (document.get("claimerId"), document.get("amount"))
                        && let (Value::Identifier(claimer_bytes), Value::U64(amount)) =
                            (claimer_value, amount_value)
                        && let Ok(claimer_id) = Identifier::from_bytes(claimer_bytes)
                        && let Err(e) =
                            self.insert_token_identity_balance(&token_id, &claimer_id, *amount)
                    {
                        tracing::error!(
                            "Failed to update token balance from claim document: {}",
                            e
                        );
                    }
                }
            }
        }

        // Return success with fee result
        use crate::backend_task::FeeResult;
        use crate::model::fee_estimation::PlatformFeeEstimator;
        let estimated_fee = PlatformFeeEstimator::new().estimate_document_batch(1);
        let fee_result = FeeResult::new(estimated_fee, estimated_fee);
        Ok(BackendTaskSuccessResult::ClaimedTokens(fee_result))
    }
}

impl AppContext {
    fn map_claim_broadcast_error_for_ui(&self, e: Error) -> String {
        match e {
            Error::DriveProofError(proof_error, proof_bytes, block_info) => {
                self.db
                    .insert_proof_log_item(ProofLogItem {
                        request_type: RequestType::BroadcastStateTransition,
                        request_bytes: vec![],
                        verification_path_query_bytes: vec![],
                        height: block_info.height,
                        time_ms: block_info.time_ms,
                        proof_bytes,
                        error: Some(proof_error.to_string()),
                    })
                    .ok();
                format!(
                    "Error broadcasting ClaimTokens transition: {}, proof error logged",
                    proof_error
                )
            }
            e => format!("Error broadcasting ClaimTokens transition: {}", e),
        }
    }
}

fn is_tx_already_exists_in_cache_error(e: &Error) -> bool {
    match e {
        Error::AlreadyExists(message) => message
            .to_ascii_lowercase()
            .contains("tx already exists in cache"),
        Error::StateTransitionBroadcastError(state_transition_error) => state_transition_error
            .message
            .to_ascii_lowercase()
            .contains("tx already exists in cache"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::is_tx_already_exists_in_cache_error;
    use dash_sdk::Error;

    #[test]
    fn classifies_tx_already_exists_in_cache_error() {
        let e = Error::AlreadyExists("tx already exists in cache".to_string());
        assert!(is_tx_already_exists_in_cache_error(&e));
    }

    #[test]
    fn classifies_tx_already_exists_in_cache_error_case_insensitive() {
        let e = Error::AlreadyExists("Tx Already Exists In Cache".to_string());
        assert!(is_tx_already_exists_in_cache_error(&e));
    }

    #[test]
    fn does_not_classify_other_already_exists_errors() {
        let e = Error::AlreadyExists("object already exists".to_string());
        assert!(!is_tx_already_exists_in_cache_error(&e));
    }

    #[test]
    fn does_not_classify_non_already_exists_errors() {
        let e = Error::Generic("network timeout".to_string());
        assert!(!is_tx_already_exists_in_cache_error(&e));
    }
}
