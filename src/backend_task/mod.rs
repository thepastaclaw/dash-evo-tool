use crate::app::TaskResult;
use crate::backend_task::error::TaskError;
use crate::backend_task::contested_names::ContestedResourceTask;
use crate::backend_task::contract::ContractTask;
use crate::backend_task::core::{CoreItem, CoreTask};
use crate::backend_task::dashpay::{DashPayTask, ContactData};
use crate::backend_task::document::DocumentTask;
use crate::backend_task::identity::IdentityTask;
use crate::backend_task::platform_info::{PlatformInfoTaskRequestType, PlatformInfoTaskResult};
use crate::backend_task::system_task::SystemTask;
use crate::backend_task::wallet::WalletTask;
use crate::context::AppContext;
use crate::spv::CoreBackendMode;
use dash_sdk::dpp::address_funds::PlatformAddress;
use dash_sdk::dpp::dashcore::Network;
use dash_sdk::dpp::dashcore::bls_sig_utils::BLSSignature;
use dash_sdk::dpp::dashcore::network::message_qrinfo::QRInfo;
use dash_sdk::dpp::dashcore::BlockHash;
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::wallet::WalletSeedHash;
use crate::model::grovestark_prover::ProofDataOutput;
use crate::ui::tokens::tokens_screen::{
    ContractDescriptionInfo, IdentityTokenIdentifier, TokenInfo,
};
use crate::utils::egui_mpsc::SenderAsync;
use contested_names::ScheduledDPNSVote;
use dash_sdk::dpp::balances::credits::TokenAmount;
use dash_sdk::dpp::dashcore::network::message_sml::MnListDiff;
use dash_sdk::dpp::data_contract::associated_token::token_perpetual_distribution::distribution_function::evaluate_interval::IntervalEvaluationExplanation;
use dash_sdk::dpp::group::group_action::GroupAction;
use dash_sdk::dpp::prelude::DataContract;
use dash_sdk::dpp::state_transition::StateTransition;
use dash_sdk::dpp::tokens::token_pricing_schedule::TokenPricingSchedule;
use dash_sdk::dpp::voting::vote_choices::resource_vote_choice::ResourceVoteChoice;
use dash_sdk::dpp::voting::votes::Vote;
use dash_sdk::platform::proto::get_documents_request::get_documents_request_v0::Start;
use dash_sdk::platform::{Document, Identifier};
use dash_sdk::query_types::{Documents, IndexMap};
use futures::future::join_all;
use std::collections::BTreeMap;
use std::sync::Arc;
use shielded::ShieldedTask;
use tokens::TokenTask;
use grovestark::GroveSTARKTask;

pub mod broadcast_state_transition;
pub mod contested_names;
pub mod contract;
pub mod core;
pub mod dapi_discovery;
pub mod dashpay;
pub mod document;
pub mod error;
pub mod grovestark;
pub mod identity;
pub mod mnlist;
pub mod platform_info;
pub mod register_contract;
pub mod shielded;
pub mod system_task;
pub mod tokens;
pub mod update_data_contract;
pub mod wallet;

// TODO: Refactor how we handle errors and messages, and remove it from here
pub(crate) const NO_IDENTITIES_FOUND: &str = "No identities found";

/// Information about fees paid for a platform state transition
#[derive(Debug, Clone, PartialEq)]
pub struct FeeResult {
    /// The fee that was estimated before the operation
    pub estimated_fee: u64,
    /// The actual fee that was paid (in credits)
    pub actual_fee: u64,
}

impl FeeResult {
    pub fn new(estimated_fee: u64, actual_fee: u64) -> Self {
        Self {
            estimated_fee,
            actual_fee,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum BackendTask {
    IdentityTask(IdentityTask),
    DocumentTask(Box<DocumentTask>),
    ContractTask(Box<ContractTask>),
    ContestedResourceTask(ContestedResourceTask),
    CoreTask(CoreTask),
    DashPayTask(Box<DashPayTask>),
    BroadcastStateTransition(StateTransition),
    TokenTask(Box<TokenTask>),
    SystemTask(SystemTask),
    MnListTask(mnlist::MnListTask),
    PlatformInfo(PlatformInfoTaskRequestType),
    GroveSTARKTask(GroveSTARKTask),
    WalletTask(WalletTask),
    ShieldedTask(ShieldedTask),
    /// Rebuild the Core RPC client and SDK on the current network context.
    /// Dispatched when the user saves a new RPC password so the reinit
    /// (which includes DAPI discovery) runs off the UI thread.
    ReinitCoreClientAndSdk,
    /// Create a new network context and switch to it.
    /// Dispatched to `AppContext::run_backend_task`, which creates the new `AppContext`
    /// and optionally starts SPV sync when `start_spv` is true.
    SwitchNetwork {
        network: Network,
        start_spv: bool,
    },
    /// Discover DAPI nodes from the DCG-operated HTTPS service.
    DiscoverDapiNodes {
        network: Network,
    },
    None,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum BackendTaskSuccessResult {
    // General results
    None,
    Refresh,
    Message(String), // Used for: placeholder messages for
    // not-yet-implemented functionality, and DashPay operations that would need their own typed variants.
    /// Progress updates during long-running operations (e.g. batch identity search).
    /// By convention, the app routes `Progress` results to the visible screen's
    /// `display_task_result` without creating a global banner at the app level
    /// (unlike `Message`). Screens may create a banner handle on first receipt
    /// and update it in-place on subsequent updates to avoid stacking.
    Progress {
        /// Human-readable progress message
        message: String,
        /// Current step (1-based)
        current: u32,
        /// Total steps
        total: u32,
    },
    WalletPayment {
        txid: String,
        /// List of (address, amount) pairs for each recipient
        recipients: Vec<(String, u64)>,
        total_amount: u64,
    },

    // Specific results
    #[allow(dead_code)] // May be used for individual document operations
    Document(Document),
    Documents(Documents),
    BroadcastedDocument(Document),
    CoreItem(CoreItem),
    RegisteredIdentity(QualifiedIdentity, FeeResult),
    ToppedUpIdentity(QualifiedIdentity, FeeResult),
    #[allow(dead_code)] // May be used for reporting successful votes
    SuccessfulVotes(Vec<Vote>),
    DPNSVoteResults(Vec<(String, ResourceVoteChoice, Result<(), String>)>),
    CastScheduledVote(ScheduledDPNSVote),
    FetchedContract(DataContract),
    FetchedContractWithTokenPosition(
        DataContract,
        dash_sdk::dpp::data_contract::TokenContractPosition,
    ),
    FetchedContracts(Vec<Option<DataContract>>),
    PageDocuments(IndexMap<Identifier, Option<Document>>, Option<Start>),
    #[allow(dead_code)] // May be used for token search results
    TokensByKeyword(Vec<TokenInfo>, Option<Start>),
    DescriptionsByKeyword(Vec<ContractDescriptionInfo>, Option<Start>),
    TokenEstimatedNonClaimedPerpetualDistributionAmountWithExplanation(
        IdentityTokenIdentifier,
        TokenAmount,
        IntervalEvaluationExplanation,
    ),
    ContractsWithDescriptions(
        BTreeMap<Identifier, (Option<ContractDescriptionInfo>, Vec<TokenInfo>)>,
    ),
    ActiveGroupActions(IndexMap<Identifier, GroupAction>),
    TokenPricing {
        token_id: Identifier,
        prices: Option<TokenPricingSchedule>,
    },
    UpdatedThemePreference(crate::ui::theme::ThemeMode),
    PlatformInfo(PlatformInfoTaskResult),

    // DashPay related results
    DashPayProfile(Option<(String, String, String)>), // (display_name, bio, avatar_url)
    DashPayContactProfile(Option<Document>),          // Contact's public profile document
    DashPayProfileSearchResults(Vec<(Identifier, Option<Document>, String)>), // Search results: (identity_id, profile_document, username)
    DashPayContactRequests {
        incoming: Vec<(Identifier, Document)>, // (request_id, document)
        outgoing: Vec<(Identifier, Document)>, // (request_id, document)
    },
    DashPayContacts(Vec<Identifier>), // List of contact identity IDs
    DashPayContactsWithInfo(Vec<ContactData>), // List of contacts with metadata
    DashPayPaymentHistory(Vec<(String, String, u64, bool, String)>), // (tx_id, contact_name, amount, is_incoming, memo)
    DashPayProfileUpdated(Identifier), // Identity ID of updated profile
    DashPayContactRequestSent(String), // Username or ID of recipient
    DashPayContactRequestAccepted(Identifier), // Request ID that was accepted
    DashPayContactRequestRejected(Identifier), // Request ID that was rejected
    DashPayContactAlreadyEstablished(Identifier), // Contact ID that already exists
    DashPayContactInfoUpdated(Identifier), // Contact ID whose info was updated
    DashPayPaymentSent(String, String, f64), // (recipient, address, amount)
    GeneratedZKProof(ProofDataOutput),
    VerifiedZKProof(bool, ProofDataOutput),
    GeneratedReceiveAddress {
        seed_hash: WalletSeedHash,
        address: String,
    },
    /// Platform address balances fetched from Platform
    PlatformAddressBalances {
        seed_hash: WalletSeedHash,
        /// Map of platform address to (balance, nonce)
        balances: BTreeMap<PlatformAddress, (u64, u32)>,
        /// Network the balances were fetched from
        network: Network,
    },
    /// Platform credits transferred between addresses
    PlatformCreditsTransferred {
        seed_hash: WalletSeedHash,
    },
    /// Platform address funded from asset lock
    PlatformAddressFunded {
        seed_hash: WalletSeedHash,
    },
    /// Withdrawal from Platform address to Core initiated
    PlatformAddressWithdrawal {
        seed_hash: WalletSeedHash,
    },

    // MNList-specific results
    MnListFetchedDiff {
        base_height: u32,
        height: u32,
        diff: MnListDiff,
    },
    MnListFetchedQrInfo {
        qr_info: QRInfo,
    },
    MnListChainLockSigs {
        entries: Vec<((u32, BlockHash), Option<BLSSignature>)>,
    },
    MnListFetchedDiffs {
        items: Vec<((u32, u32), MnListDiff)>,
    },

    // Token operation results (replacing string messages)
    PausedTokens(FeeResult),
    ResumedTokens(FeeResult),
    MintedTokens(FeeResult),
    BurnedTokens(FeeResult),
    FrozeTokens(FeeResult),
    UnfrozeTokens(FeeResult),
    TransferredTokens(FeeResult),
    PurchasedTokens(FeeResult),
    SetTokenPrice(FeeResult),
    DestroyedFrozenFunds(FeeResult),
    ClaimedTokens(FeeResult),
    UpdatedTokenConfig(String, FeeResult), // The config item that was updated
    FetchedTokenBalances,
    SavedToken,

    // Identity operation results (replacing string messages)
    AddedKeyToIdentity(FeeResult),
    TransferredCredits(FeeResult),
    WithdrewFromIdentity(FeeResult),
    RegisteredDpnsName(FeeResult),
    RefreshedIdentity(QualifiedIdentity),
    LoadedIdentity(QualifiedIdentity),

    // Document operation results (replacing string messages)
    DeletedDocument(Identifier, FeeResult),
    ReplacedDocument(Identifier, FeeResult),
    TransferredDocument(Identifier, FeeResult),
    PurchasedDocument(Identifier, FeeResult),
    SetDocumentPrice(Identifier, FeeResult),

    // Contract operation results (replacing string messages)
    UpdatedContract(FeeResult),
    RemovedContract,
    FetchedNonce,
    RegisteredContract(FeeResult),
    RegisteredTokenContract,
    SavedContract,
    ContractNotFound,
    TokenNotFound,
    ProofErrorLogged,
    /// Contract was saved to the local database despite a proof verification error.
    /// Sent by `register_data_contract` / `update_data_contract` when the contract was
    /// successfully fetched from Platform and stored after a `DriveProofError`.
    ContractSavedAfterProofError,

    // Wallet operation results (replacing string messages)
    RefreshedWallet {
        /// Optional warning message (e.g., Platform sync failed but Core refresh succeeded)
        warning: Option<String>,
    },
    RecoveredAssetLocks {
        recovered_count: usize,
        total_amount: u64,
    },

    // DPNS operation results (replacing string messages)
    ScheduledVotes,
    RefreshedDpnsContests,
    RefreshedOwnedDpnsNames,

    // Broadcast results
    BroadcastedStateTransition,

    // Mining results (dev mode, Regtest/Devnet only)
    MineBlocksSuccess(u64),

    // Core wallet list (async fetch of loaded Core wallets)
    CoreWalletsList(Vec<String>),

    // Shielded pool results
    ShieldedInitialized {
        seed_hash: WalletSeedHash,
        balance: u64,
    },
    ShieldedNotesSynced {
        seed_hash: WalletSeedHash,
        new_notes: u32,
        balance: u64,
    },
    ShieldedCreditsShielded {
        seed_hash: WalletSeedHash,
        amount: u64,
    },
    ShieldedTransferComplete {
        seed_hash: WalletSeedHash,
        amount: u64,
    },
    ShieldedCreditsUnshielded {
        seed_hash: WalletSeedHash,
        amount: u64,
    },
    ShieldedNullifiersChecked {
        seed_hash: WalletSeedHash,
        spent_count: u32,
    },
    ShieldedFromAssetLock {
        seed_hash: WalletSeedHash,
        amount: u64,
    },
    ShieldedWithdrawalComplete {
        seed_hash: WalletSeedHash,
        amount: u64,
    },
    ProvingKeyReady,

    /// Core RPC client and SDK were successfully rebuilt (e.g. after password change).
    CoreClientReinitialized,

    /// A new network context was created asynchronously during a network switch.
    NetworkContextCreated {
        network: Network,
        context: Arc<AppContext>,
        spv_started: bool,
    },

    /// Fresh DAPI node addresses discovered from the DCG service.
    DapiNodesDiscovered {
        network: Network,
        count: usize,
        addresses_csv: String,
    },
}

impl BackendTaskSuccessResult {}

impl BackendTask {
    /// Whether this task issues DAPI/SDK calls that perform proof verification
    /// against quorum & masternode-list data sourced from SPV. If `true`,
    /// dispatch must wait for SPV to reach `Synced` before running the task,
    /// otherwise the SDK will fail deep inside proof verification with an
    /// opaque error.
    ///
    /// Audit (must be kept in sync with `run_backend_task`):
    ///
    /// - Gated (DAPI/SDK proof-verifying):
    ///   - `ContractTask`, `ContestedResourceTask`, `IdentityTask`,
    ///     `DocumentTask`, `DashPayTask`, `BroadcastStateTransition`,
    ///     `TokenTask`, `PlatformInfo`, `GroveSTARKTask` — all variants are
    ///     Platform queries / broadcasts.
    ///   - `WalletTask` — all variants except `GenerateReceiveAddress` touch
    ///     Platform addresses (balances, transfers, withdrawals,
    ///     funding-from-asset-lock, funding-from-utxos).
    ///   - `ShieldedTask` — all variants except `WarmUpProvingKey` interact
    ///     with the Platform shielded pool (sync, shield, transfer,
    ///     unshield, nullifier checks, withdrawal).
    ///
    /// - Not gated (local / Core-only / discovery / system):
    ///   - `CoreTask` — uses Core RPC or SPV directly, never DAPI. (The
    ///     `RefreshWalletInfo(_, sync_platform=true)` path internally calls
    ///     `fetch_platform_address_balances`, but that already surfaces a
    ///     soft "Platform sync failed" warning rather than a hard error,
    ///     which is the historical behaviour.)
    ///   - `MnListTask` — uses Core P2P directly, no DAPI.
    ///   - `SystemTask` — local DB / preferences only.
    ///   - `ReinitCoreClientAndSdk`, `SwitchNetwork`, `DiscoverDapiNodes`,
    ///     `None` — bootstrap / discovery; gating these would deadlock the
    ///     very subsystems the gate depends on.
    pub fn requires_spv_ready_for_dapi(&self) -> bool {
        match self {
            BackendTask::ContractTask(_)
            | BackendTask::ContestedResourceTask(_)
            | BackendTask::IdentityTask(_)
            | BackendTask::DocumentTask(_)
            | BackendTask::DashPayTask(_)
            | BackendTask::BroadcastStateTransition(_)
            | BackendTask::TokenTask(_)
            | BackendTask::PlatformInfo(_)
            | BackendTask::GroveSTARKTask(_) => true,

            BackendTask::WalletTask(t) => t.requires_spv_ready_for_dapi(),
            BackendTask::ShieldedTask(t) => t.requires_spv_ready_for_dapi(),

            BackendTask::CoreTask(_)
            | BackendTask::MnListTask(_)
            | BackendTask::SystemTask(_)
            | BackendTask::ReinitCoreClientAndSdk
            | BackendTask::SwitchNetwork { .. }
            | BackendTask::DiscoverDapiNodes { .. }
            | BackendTask::None => false,
        }
    }
}

impl WalletTask {
    /// See [`BackendTask::requires_spv_ready_for_dapi`]. Only
    /// `GenerateReceiveAddress` is purely local; every other variant queries
    /// or mutates Platform address state via the SDK.
    pub fn requires_spv_ready_for_dapi(&self) -> bool {
        match self {
            WalletTask::GenerateReceiveAddress { .. } => false,
            WalletTask::FetchPlatformAddressBalances { .. }
            | WalletTask::TransferPlatformCredits { .. }
            | WalletTask::FundPlatformAddressFromAssetLock { .. }
            | WalletTask::WithdrawFromPlatformAddress { .. }
            | WalletTask::FundPlatformAddressFromWalletUtxos { .. } => true,
        }
    }
}

impl ShieldedTask {
    /// See [`BackendTask::requires_spv_ready_for_dapi`]. `WarmUpProvingKey`
    /// is a CPU-only Orchard proving-key precomputation with no network
    /// calls. Every other variant interacts with the Platform shielded pool.
    pub fn requires_spv_ready_for_dapi(&self) -> bool {
        match self {
            ShieldedTask::WarmUpProvingKey => false,
            ShieldedTask::InitializeShieldedWallet { .. }
            | ShieldedTask::SyncNotes { .. }
            | ShieldedTask::ShieldCredits { .. }
            | ShieldedTask::ShieldedTransfer { .. }
            | ShieldedTask::UnshieldCredits { .. }
            | ShieldedTask::CheckNullifiers { .. }
            | ShieldedTask::ShieldFromAssetLock { .. }
            | ShieldedTask::ShieldedWithdrawal { .. } => true,
        }
    }
}

impl AppContext {
    /// Run backend tasks sequentially
    pub async fn run_backend_tasks_sequential(
        self: &Arc<Self>,
        tasks: Vec<BackendTask>,
        sender: SenderAsync<TaskResult>,
    ) -> Vec<Result<BackendTaskSuccessResult, TaskError>> {
        let mut results = Vec::new();
        for task in tasks {
            match self.run_backend_task(task, sender.clone()).await {
                Ok(result) => results.push(Ok(result)),
                Err(e) => results.push(Err(e)),
            };
        }
        results
    }

    /// Run backend tasks concurrently
    pub async fn run_backend_tasks_concurrent(
        self: &Arc<Self>,
        tasks: Vec<BackendTask>,
        sender: SenderAsync<TaskResult>,
    ) -> Vec<Result<BackendTaskSuccessResult, TaskError>> {
        let futures = tasks
            .into_iter()
            .map(|task| {
                let cloned_self = Arc::clone(self);
                let cloned_sender = sender.clone();
                async move { cloned_self.run_backend_task(task, cloned_sender).await }
            })
            .collect::<Vec<_>>();

        // Wait for all to finish before returning
        join_all(futures).await
    }

    pub async fn run_backend_task(
        self: &Arc<Self>,
        task: BackendTask,
        sender: SenderAsync<TaskResult>,
    ) -> Result<BackendTaskSuccessResult, TaskError> {
        // Block DAPI/SDK proof-verifying tasks until SPV has finished its
        // initial sync. Without this gate the SDK's quorum cache is empty
        // and any proof verification fails with a confusing
        // "quorum public key not found" error. See
        // [`BackendTask::requires_spv_ready_for_dapi`] for the audited list
        // of gated vs. non-gated families.
        if task.requires_spv_ready_for_dapi() {
            self.await_spv_ready(crate::context::connection_status::SPV_WAIT_DEFAULT_TIMEOUT)
                .await?;
        }
        let sdk = self.sdk.load().as_ref().clone();
        match task {
            BackendTask::ContractTask(contract_task) => {
                Ok(self.run_contract_task(*contract_task, &sdk, sender).await?)
            }
            BackendTask::ContestedResourceTask(contested_resource_task) => Ok(self
                .run_contested_resource_task(contested_resource_task, &sdk, sender)
                .await?),
            BackendTask::IdentityTask(identity_task) => {
                Ok(self.run_identity_task(identity_task, &sdk, sender).await?)
            }
            BackendTask::DocumentTask(document_task) => {
                Ok(self.run_document_task(*document_task, &sdk).await?)
            }
            BackendTask::CoreTask(core_task) => Ok(self.run_core_task(core_task).await?),
            BackendTask::DashPayTask(dashpay_task) => {
                Ok(self.run_dashpay_task(*dashpay_task, &sdk).await?)
            }
            BackendTask::BroadcastStateTransition(state_transition) => Ok(self
                .broadcast_state_transition(state_transition, &sdk)
                .await?),
            BackendTask::TokenTask(token_task) => {
                Ok(self.run_token_task(*token_task, &sdk, sender).await?)
            }
            BackendTask::SystemTask(system_task) => {
                Ok(self.run_system_task(system_task, sender).await?)
            }
            BackendTask::MnListTask(mnlist_task) => {
                Ok(mnlist::run_mnlist_task(self, mnlist_task).await?)
            }
            BackendTask::PlatformInfo(platform_info_task) => Ok(self
                .run_platform_info_task(platform_info_task, &sdk)
                .await?),
            BackendTask::GroveSTARKTask(grovestark_task) => {
                Ok(grovestark::run_grovestark_task(grovestark_task, &sdk).await?)
            }
            BackendTask::WalletTask(wallet_task) => Ok(self.run_wallet_task(wallet_task).await?),
            BackendTask::ShieldedTask(shielded_task) => {
                Ok(self.run_shielded_task(shielded_task).await?)
            }
            BackendTask::ReinitCoreClientAndSdk => {
                Arc::clone(self).reinit_core_client_and_sdk()?;
                Ok(BackendTaskSuccessResult::CoreClientReinitialized)
            }
            BackendTask::SwitchNetwork { network, start_spv } => {
                // Create a new AppContext for the target network, reusing shared
                // resources (db, subtasks, connection_status) from the current context.
                // Wrapped in block_in_place because AppContext::new() does DB init
                // and file I/O which would block the async runtime.
                let data_dir = self.data_dir.clone();
                let db = self.db.clone();
                let password_info = self.password_info.clone();
                let subtasks = self.subtasks.clone();
                let connection_status = self.connection_status.clone();
                let egui_ctx = self.egui_ctx().clone();
                let new_ctx = tokio::task::block_in_place(|| {
                    AppContext::new(
                        data_dir,
                        network,
                        db,
                        password_info,
                        subtasks,
                        connection_status,
                        egui_ctx,
                    )
                })
                .ok_or(TaskError::NetworkContextCreationFailed {
                    network,
                    detail: "AppContext::new() returned None".into(),
                })?;

                let spv_started = if start_spv {
                    if new_ctx.core_backend_mode() != CoreBackendMode::Spv {
                        new_ctx.set_core_backend_mode_volatile(CoreBackendMode::Spv);
                    }
                    match new_ctx.start_spv() {
                        Ok(()) => {
                            tracing::info!(?network, "SPV started after network switch");
                            true
                        }
                        Err(e) => {
                            tracing::warn!(?network, "SPV start failed after network switch: {e}");
                            false
                        }
                    }
                } else {
                    false
                };
                Ok(BackendTaskSuccessResult::NetworkContextCreated {
                    network,
                    context: new_ctx,
                    spv_started,
                })
            }
            BackendTask::DiscoverDapiNodes { network } => {
                let devnet_name = self
                    .config
                    .read()
                    .map_err(|_| TaskError::LockPoisoned {
                        resource: "NetworkConfig",
                    })?
                    .devnet_name
                    .clone();
                let (count, addresses_csv) =
                    dapi_discovery::discover_and_format(network, devnet_name.as_deref()).await?;
                Ok(BackendTaskSuccessResult::DapiNodesDiscovered {
                    network,
                    count,
                    addresses_csv,
                })
            }
            BackendTask::None => Ok(BackendTaskSuccessResult::None),
        }
    }

    async fn run_wallet_task(
        self: &Arc<Self>,
        task: WalletTask,
    ) -> Result<BackendTaskSuccessResult, TaskError> {
        match task {
            WalletTask::GenerateReceiveAddress { seed_hash } => {
                self.generate_receive_address(seed_hash).await
            }
            WalletTask::FetchPlatformAddressBalances { seed_hash } => {
                self.fetch_platform_address_balances(seed_hash).await
            }
            WalletTask::TransferPlatformCredits {
                seed_hash,
                inputs,
                outputs,
                fee_payer_index,
            } => {
                self.transfer_platform_credits(seed_hash, inputs, outputs, fee_payer_index)
                    .await
            }
            WalletTask::FundPlatformAddressFromAssetLock {
                seed_hash,
                asset_lock_proof,
                asset_lock_address,
                outputs,
            } => {
                self.fund_platform_address_from_asset_lock(
                    seed_hash,
                    *asset_lock_proof,
                    asset_lock_address,
                    outputs,
                )
                .await
            }
            WalletTask::WithdrawFromPlatformAddress {
                seed_hash,
                inputs,
                output_script,
                core_fee_per_byte,
                fee_payer_index,
            } => {
                self.withdraw_from_platform_address(
                    seed_hash,
                    inputs,
                    output_script,
                    core_fee_per_byte,
                    fee_payer_index,
                )
                .await
            }
            WalletTask::FundPlatformAddressFromWalletUtxos {
                seed_hash,
                amount,
                destination,
                fee_deduct_from_output,
            } => {
                self.fund_platform_address_from_wallet_utxos(
                    seed_hash,
                    amount,
                    destination,
                    fee_deduct_from_output,
                )
                .await
            }
        }
    }
}

#[cfg(test)]
mod gating_tests {
    //! Tests that pin down which `BackendTask` families must wait for SPV to
    //! reach `Synced` before invoking the SDK.
    //!
    //! These are deliberately exhaustive (sub-task helpers use `match` with
    //! every variant explicit) so that adding a new task variant becomes a
    //! compile error until the author has consciously decided whether the
    //! variant calls into DAPI/SDK proof verification or not. The intent is
    //! to keep the gate honest as the codebase grows.
    use super::*;

    #[test]
    fn local_only_tasks_are_not_gated() {
        assert!(!BackendTask::None.requires_spv_ready_for_dapi());
        assert!(!BackendTask::ReinitCoreClientAndSdk.requires_spv_ready_for_dapi());
        assert!(
            !BackendTask::SwitchNetwork {
                network: Network::Testnet,
                start_spv: false,
            }
            .requires_spv_ready_for_dapi()
        );
        assert!(
            !BackendTask::DiscoverDapiNodes {
                network: Network::Testnet,
            }
            .requires_spv_ready_for_dapi()
        );
        assert!(
            !BackendTask::SystemTask(SystemTask::WipePlatformData).requires_spv_ready_for_dapi()
        );
        assert!(
            !BackendTask::MnListTask(mnlist::MnListTask::FetchChainLocks {
                base_block_height: 0,
                block_height: 0,
            })
            .requires_spv_ready_for_dapi()
        );
    }

    #[test]
    fn wallet_task_local_variant_is_not_gated() {
        let t = WalletTask::GenerateReceiveAddress {
            seed_hash: [0u8; 32],
        };
        assert!(!t.requires_spv_ready_for_dapi());
        assert!(!BackendTask::WalletTask(t).requires_spv_ready_for_dapi());
    }

    #[test]
    fn wallet_task_platform_variants_are_gated() {
        let t = WalletTask::FetchPlatformAddressBalances {
            seed_hash: [0u8; 32],
        };
        assert!(t.requires_spv_ready_for_dapi());
        assert!(BackendTask::WalletTask(t).requires_spv_ready_for_dapi());
    }

    #[test]
    fn shielded_warmup_is_not_gated() {
        let t = ShieldedTask::WarmUpProvingKey;
        assert!(!t.requires_spv_ready_for_dapi());
        assert!(!BackendTask::ShieldedTask(t).requires_spv_ready_for_dapi());
    }

    #[test]
    fn shielded_platform_variants_are_gated() {
        let t = ShieldedTask::SyncNotes {
            seed_hash: [0u8; 32],
        };
        assert!(t.requires_spv_ready_for_dapi());
        assert!(BackendTask::ShieldedTask(t).requires_spv_ready_for_dapi());

        let t = ShieldedTask::CheckNullifiers {
            seed_hash: [0u8; 32],
        };
        assert!(t.requires_spv_ready_for_dapi());
        assert!(BackendTask::ShieldedTask(t).requires_spv_ready_for_dapi());
    }

    #[test]
    fn identity_task_refresh_is_gated() {
        // Pick the simplest-to-construct IdentityTask variant; the helper is
        // family-level (any IdentityTask is gated) so this is sufficient to
        // pin the IdentityTask arm in the classifier.
        let t = BackendTask::IdentityTask(IdentityTask::RefreshLoadedIdentitiesOwnedDPNSNames);
        assert!(t.requires_spv_ready_for_dapi());
    }
}
