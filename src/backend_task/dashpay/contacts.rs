use crate::backend_task::BackendTaskSuccessResult;
use crate::context::AppContext;
use crate::model::qualified_identity::QualifiedIdentity;
use dash_sdk::Sdk;
use dash_sdk::dpp::data_contract::DataContract;
use dash_sdk::dpp::document::DocumentV0Getters;
use dash_sdk::dpp::identity::accessors::IdentityGettersV0;
use dash_sdk::dpp::key_wallet::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
use dash_sdk::dpp::platform_value::Value;
use dash_sdk::drive::query::{OrderClause, WhereClause, WhereOperator};
use dash_sdk::platform::proto::get_documents_request::get_documents_request_v0::Start;
use dash_sdk::platform::{Document, DocumentQuery, Fetch, FetchMany, Identifier};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

/// Page size used when paginating through DashPay queries.
const DASHPAY_QUERY_PAGE_SIZE: u32 = 100;

// DashPay contract ID from the platform repo
pub const DASHPAY_CONTRACT_ID: [u8; 32] = [
    162, 161, 180, 172, 111, 239, 34, 234, 42, 26, 104, 232, 18, 54, 68, 179, 87, 135, 95, 107, 65,
    44, 24, 16, 146, 129, 193, 70, 231, 178, 113, 188,
];

pub async fn get_dashpay_contract(sdk: &Sdk) -> Result<Arc<DataContract>, String> {
    let contract_id = Identifier::from_bytes(&DASHPAY_CONTRACT_ID).map_err(|e| e.to_string())?;
    DataContract::fetch(sdk, contract_id)
        .await
        .map_err(|e| format!("Failed to fetch DashPay contract: {}", e))?
        .ok_or_else(|| "DashPay contract not found".to_string())
        .map(Arc::new)
}

/// Derive encryption keys for contactInfo using BIP32 CKDpriv as specified in DIP-0015.
///
/// DIP-0015 specifies:
/// - Key1 (for encToUserId): rootEncryptionKey/(2^16)'/index'
/// - Key2 (for privateData): rootEncryptionKey/(2^16 + 1)'/index'
///
/// We use the wallet's master seed to derive a root encryption key,
/// then apply BIP32 hardened derivation for the two encryption keys.
fn derive_contact_info_keys(
    identity: &QualifiedIdentity,
    derivation_index: u32,
) -> Result<([u8; 32], [u8; 32]), String> {
    // Get the wallet seed from the identity's associated wallet
    let wallet = identity
        .associated_wallets
        .values()
        .next()
        .ok_or("No wallet associated with identity for key derivation")?;

    let (seed, network) = {
        let wallet_guard = wallet.read().map_err(|e| e.to_string())?;
        if !wallet_guard.is_open() {
            return Err("Wallet must be unlocked to derive encryption keys".to_string());
        }
        let seed = wallet_guard
            .seed_bytes()
            .map_err(|e| format!("Wallet seed not available: {}", e))?
            .to_vec();
        (seed, identity.network)
    };

    // Create master extended private key from seed
    let master_xprv = ExtendedPrivKey::new_master(network, &seed)
        .map_err(|e| format!("Failed to create master key: {}", e))?;

    // Derive to the root encryption key path: m/9'/5'/15'/0'
    // This follows the DashPay derivation structure
    let root_path = DerivationPath::from_str("m/9'/5'/15'/0'")
        .map_err(|e| format!("Invalid derivation path: {}", e))?;

    let secp = dash_sdk::dpp::dashcore::secp256k1::Secp256k1::new();
    let root_encryption_key = master_xprv
        .derive_priv(&secp, &root_path)
        .map_err(|e| format!("Failed to derive root encryption key: {}", e))?;

    // Derive Key1 for encToUserId: rootEncryptionKey/(2^16)'/index'
    // First derive at hardened index 2^16 (65536)
    let key1_level1 = root_encryption_key
        .derive_priv(
            &secp,
            &[ChildNumber::from_hardened_idx(65536)
                .map_err(|e| format!("Invalid hardened index: {}", e))?],
        )
        .map_err(|e| format!("Failed to derive key1 level1: {}", e))?;

    // Then derive at hardened derivation_index
    let key1_final = key1_level1
        .derive_priv(
            &secp,
            &[ChildNumber::from_hardened_idx(derivation_index)
                .map_err(|e| format!("Invalid hardened index: {}", e))?],
        )
        .map_err(|e| format!("Failed to derive key1 final: {}", e))?;

    // Derive Key2 for privateData: rootEncryptionKey/(2^16 + 1)'/index'
    // First derive at hardened index 2^16 + 1 (65537)
    let key2_level1 = root_encryption_key
        .derive_priv(
            &secp,
            &[ChildNumber::from_hardened_idx(65537)
                .map_err(|e| format!("Invalid hardened index: {}", e))?],
        )
        .map_err(|e| format!("Failed to derive key2 level1: {}", e))?;

    // Then derive at hardened derivation_index
    let key2_final = key2_level1
        .derive_priv(
            &secp,
            &[ChildNumber::from_hardened_idx(derivation_index)
                .map_err(|e| format!("Invalid hardened index: {}", e))?],
        )
        .map_err(|e| format!("Failed to derive key2 final: {}", e))?;

    // Extract the private key bytes (32 bytes) for encryption
    let key1_bytes: [u8; 32] = key1_final.private_key.secret_bytes();
    let key2_bytes: [u8; 32] = key2_final.private_key.secret_bytes();

    Ok((key1_bytes, key2_bytes))
}

/// Decrypt toUserId using AES-256-ECB as specified by DIP-0015.
///
/// DIP-0015 mandates ECB mode for encToUserId encryption because:
/// 1. The toUserId is derived from SHA256, making it appear random (no patterns)
/// 2. Keys are never reused (unique per contact via hardened BIP32 derivation)
/// 3. The data is fixed-size (32 bytes = exactly 2 AES blocks)
///
/// These properties eliminate typical ECB vulnerabilities (pattern leakage).
/// See: https://github.com/dashpay/dips/blob/master/dip-0015.md
#[allow(deprecated)]
fn decrypt_to_user_id(encrypted: &[u8], key: &[u8; 32]) -> Result<[u8; 32], String> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aes::Aes256;
    use aes_gcm::aes::cipher::{BlockDecrypt, KeyInit};

    if encrypted.len() != 32 {
        return Err("Invalid encrypted user ID length".to_string());
    }

    let cipher = Aes256::new(GenericArray::from_slice(key));

    // Split the 32-byte encrypted data into two 16-byte blocks for ECB mode
    let mut decrypted = [0u8; 32];

    let mut block1 = GenericArray::clone_from_slice(&encrypted[0..16]);
    let mut block2 = GenericArray::clone_from_slice(&encrypted[16..32]);

    cipher.decrypt_block(&mut block1);
    cipher.decrypt_block(&mut block2);

    decrypted[0..16].copy_from_slice(&block1);
    decrypted[16..32].copy_from_slice(&block2);

    Ok(decrypted)
}

// Helper function to decrypt private data using AES-256-CBC
fn decrypt_private_data(encrypted_data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    use cbc::cipher::BlockDecryptMut;
    use cbc::cipher::KeyIvInit;
    use cbc::cipher::block_padding::Pkcs7;
    type Aes256CbcDec = cbc::Decryptor<aes_gcm::aes::Aes256>;

    if encrypted_data.len() < 16 {
        return Err("Encrypted data too short (no IV)".to_string());
    }

    // Extract IV and ciphertext
    let iv = &encrypted_data[0..16];
    let ciphertext = &encrypted_data[16..];

    // Decrypt
    let cipher = Aes256CbcDec::new(key.into(), iv.into());

    let mut buffer = ciphertext.to_vec();
    let decrypted = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|e| format!("Decryption failed: {:?}", e))?;

    Ok(decrypted.to_vec())
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContactData {
    pub identity_id: Identifier,
    pub nickname: Option<String>,
    pub note: Option<String>,
    pub is_hidden: bool,
    pub account_reference: u32,
    // Profile data (fetched from Platform)
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
}

/// Fetch all documents matching `query`, paginating through pages of `DASHPAY_QUERY_PAGE_SIZE`
/// using `Start::StartAfter(last_doc_id)` until fewer than a full page is returned.
///
/// `context` is included in error messages to identify which query failed.
async fn fetch_all_documents_paginated(
    sdk: &Sdk,
    mut query: DocumentQuery,
    context: &str,
) -> Result<Vec<(Identifier, Document)>, String> {
    query.limit = DASHPAY_QUERY_PAGE_SIZE;
    let mut all: Vec<(Identifier, Document)> = Vec::new();

    loop {
        let page = Document::fetch_many(sdk, query.clone())
            .await
            .map_err(|e| format!("Error fetching {}: {}", context, e))?;

        let page_len = page.len();
        let last_id = page.keys().last().copied();

        for (id, doc_opt) in page {
            if let Some(doc) = doc_opt {
                all.push((id, doc));
            }
        }

        if page_len < DASHPAY_QUERY_PAGE_SIZE as usize {
            break;
        }
        let Some(last_id) = last_id else { break };
        query.start = Some(Start::StartAfter(last_id.to_buffer().to_vec()));
    }

    Ok(all)
}

/// Compute the set of mutual contacts: identities present both as the owner of an
/// incoming contactRequest and as the `toUserId` of an outgoing contactRequest.
///
/// Pure helper extracted so the intersection logic can be unit tested without
/// constructing live `Document`s.
pub(crate) fn find_mutual_contacts<I, O>(
    incoming_owner_ids: I,
    outgoing_to_user_ids: O,
) -> HashSet<Identifier>
where
    I: IntoIterator<Item = Identifier>,
    O: IntoIterator<Item = Identifier>,
{
    let outgoing_set: HashSet<Identifier> = outgoing_to_user_ids.into_iter().collect();
    incoming_owner_ids
        .into_iter()
        .filter(|id| outgoing_set.contains(id))
        .collect()
}

pub async fn load_contacts(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    identity: QualifiedIdentity,
) -> Result<BackendTaskSuccessResult, String> {
    let identity_id = identity.identity.id();
    let dashpay_contract = app_context.dashpay_contract.clone();

    // Query for contact requests where we are the sender (ownerId).
    // The explicit $createdAt orderBy is a workaround for the Platform bug where
    // queries without an orderBy can return 0 results even when documents exist
    // (matches the workaround used in contact_requests.rs::load_contact_requests).
    let mut outgoing_query = DocumentQuery::new(dashpay_contract.clone(), "contactRequest")
        .map_err(|e| format!("Failed to create query: {}", e))?;
    outgoing_query = outgoing_query
        .with_where(WhereClause {
            field: "$ownerId".to_string(),
            operator: WhereOperator::Equal,
            value: Value::Identifier(identity_id.to_buffer()),
        })
        .with_order_by(OrderClause {
            field: "$createdAt".to_string(),
            ascending: true,
        });

    // Query for contact requests where we are the recipient (toUserId).
    let mut incoming_query = DocumentQuery::new(dashpay_contract.clone(), "contactRequest")
        .map_err(|e| format!("Failed to create query: {}", e))?;
    incoming_query = incoming_query
        .with_where(WhereClause {
            field: "toUserId".to_string(),
            operator: WhereOperator::Equal,
            value: Value::Identifier(identity_id.to_buffer()),
        })
        .with_order_by(OrderClause {
            field: "$createdAt".to_string(),
            ascending: true,
        });

    // Fetch all pages so identities with many contacts don't lose reciprocal matches
    // because of a fixed first-page limit.
    let outgoing =
        fetch_all_documents_paginated(sdk, outgoing_query, "outgoing contact requests").await?;
    let incoming =
        fetch_all_documents_paginated(sdk, incoming_query, "incoming contact requests").await?;

    // Find mutual contacts (where both parties have sent requests to each other)
    let incoming_owner_ids = incoming.iter().map(|(_, doc)| doc.owner_id());
    let outgoing_to_user_ids =
        outgoing
            .iter()
            .filter_map(|(_, doc)| match doc.properties().get("toUserId") {
                Some(Value::Identifier(to_id_bytes)) => {
                    match Identifier::from_bytes(to_id_bytes.as_slice()) {
                        Ok(id) => Some(id),
                        Err(_) => {
                            tracing::warn!("Invalid toUserId in outgoing contactRequest, skipping");
                            None
                        }
                    }
                }
                _ => None,
            });
    let contacts = find_mutual_contacts(incoming_owner_ids, outgoing_to_user_ids);

    // Now query for contact info documents (also paginated).
    let mut contact_info_query = DocumentQuery::new(dashpay_contract.clone(), "contactInfo")
        .map_err(|e| format!("Failed to create query: {}", e))?;

    contact_info_query = contact_info_query.with_where(WhereClause {
        field: "$ownerId".to_string(),
        operator: WhereOperator::Equal,
        value: Value::Identifier(identity_id.to_buffer()),
    });

    let contact_info_docs =
        fetch_all_documents_paginated(sdk, contact_info_query, "contact info").await?;

    // Build a map of contact ID to contact info
    let mut contact_info_map: HashMap<Identifier, ContactData> = HashMap::new();

    for (_doc_id, doc) in contact_info_docs.iter() {
        let props = doc.properties();

        // Get the derivation index used for this document
        if let Some(Value::U32(deriv_idx)) = props.get("derivationEncryptionKeyIndex") {
            // Derive keys for this document
            let (enc_user_id_key, private_data_key) =
                match derive_contact_info_keys(&identity, *deriv_idx) {
                    Ok(keys) => keys,
                    Err(_) => continue,
                };

            // Decrypt encToUserId to find which contact this is for
            if let Some(Value::Bytes(enc_user_id)) = props.get("encToUserId")
                && let Ok(decrypted_id) = decrypt_to_user_id(enc_user_id, &enc_user_id_key)
            {
                let Ok(contact_id) = Identifier::from_bytes(&decrypted_id) else {
                    tracing::warn!("Decrypted contact id was not a valid Identifier, skipping");
                    continue;
                };

                // Decrypt private data if available
                let mut nickname = None;
                let mut note = None;
                let mut is_hidden = false;
                let mut account_reference = 0u32;

                if let Some(Value::Bytes(encrypted_private)) = props.get("privateData")
                    && let Ok(decrypted_data) =
                        decrypt_private_data(encrypted_private, &private_data_key)
                {
                    // Parse the decrypted data
                    // Simple format: version(4) + alias_len(1) + alias + note_len(1) + note + hidden(1) + accounts_len(1) + accounts
                    if decrypted_data.len() >= 8 {
                        let mut pos = 4; // Skip version

                        // Read alias
                        if pos < decrypted_data.len() {
                            let alias_len = decrypted_data[pos] as usize;
                            pos += 1;
                            if pos + alias_len <= decrypted_data.len() && alias_len > 0 {
                                nickname = String::from_utf8(
                                    decrypted_data[pos..pos + alias_len].to_vec(),
                                )
                                .ok();
                                pos += alias_len;
                            }
                        }

                        // Read note
                        if pos < decrypted_data.len() {
                            let note_len = decrypted_data[pos] as usize;
                            pos += 1;
                            if pos + note_len <= decrypted_data.len() && note_len > 0 {
                                note =
                                    String::from_utf8(decrypted_data[pos..pos + note_len].to_vec())
                                        .ok();
                                pos += note_len;
                            }
                        }

                        // Read hidden flag
                        if pos < decrypted_data.len() {
                            is_hidden = decrypted_data[pos] != 0;
                            pos += 1;
                        }

                        // Read accounts (simplified - just take first if available)
                        if pos < decrypted_data.len() {
                            let accounts_len = decrypted_data[pos] as usize;
                            pos += 1;
                            if accounts_len > 0 && pos + 4 <= decrypted_data.len() {
                                account_reference = u32::from_le_bytes([
                                    decrypted_data[pos],
                                    decrypted_data[pos + 1],
                                    decrypted_data[pos + 2],
                                    decrypted_data[pos + 3],
                                ]);
                            }
                        }
                    }
                }

                contact_info_map.insert(
                    contact_id,
                    ContactData {
                        identity_id: contact_id,
                        nickname,
                        note,
                        is_hidden,
                        account_reference,
                        username: None,
                        display_name: None,
                        avatar_url: None,
                        bio: None,
                    },
                );
            }
        }
    }

    // Build enriched contact list with basic data
    let mut contact_list: Vec<ContactData> = contacts
        .into_iter()
        .map(|contact_id| {
            contact_info_map
                .get(&contact_id)
                .cloned()
                .unwrap_or(ContactData {
                    identity_id: contact_id,
                    nickname: None,
                    note: None,
                    is_hidden: false,
                    account_reference: 0,
                    username: None,
                    display_name: None,
                    avatar_url: None,
                    bio: None,
                })
        })
        .collect();

    // Fetch profiles and usernames for all contacts
    // First, collect all contact IDs
    let contact_ids: Vec<Identifier> = contact_list.iter().map(|c| c.identity_id).collect();

    // Fetch profiles for all contacts (batch query)
    if !contact_ids.is_empty() {
        // Query profiles for all contacts
        for contact_id in &contact_ids {
            // Fetch profile
            let mut profile_query = DocumentQuery::new(dashpay_contract.clone(), "profile")
                .map_err(|e| format!("Failed to create profile query: {}", e))?;

            profile_query = profile_query.with_where(WhereClause {
                field: "$ownerId".to_string(),
                operator: WhereOperator::Equal,
                value: Value::Identifier(contact_id.to_buffer()),
            });
            profile_query.limit = 1;

            if let Ok(results) = Document::fetch_many(sdk, profile_query).await
                && let Some((_, Some(doc))) = results.into_iter().next()
            {
                let props = doc.properties();

                let display_name = props
                    .get("displayName")
                    .and_then(|v| v.as_text())
                    .map(|s| s.to_string());

                let avatar_url = props
                    .get("avatarUrl")
                    .and_then(|v| v.as_text())
                    .map(|s| s.to_string());

                let bio = props
                    .get("bio")
                    .and_then(|v| v.as_text())
                    .map(|s| s.to_string());

                // Update the contact in the list
                if let Some(contact) = contact_list
                    .iter_mut()
                    .find(|c| c.identity_id == *contact_id)
                {
                    contact.display_name = display_name;
                    contact.avatar_url = avatar_url;
                    contact.bio = bio;
                }
            }

            // Fetch DPNS username
            let dpns_contract = app_context.dpns_contract.clone();
            let mut dpns_query = DocumentQuery::new(dpns_contract, "domain")
                .map_err(|e| format!("Failed to create DPNS query: {}", e))?;

            dpns_query = dpns_query.with_where(WhereClause {
                field: "records.identity".to_string(),
                operator: WhereOperator::Equal,
                value: Value::Identifier(contact_id.to_buffer()),
            });
            dpns_query.limit = 1;

            if let Ok(results) = Document::fetch_many(sdk, dpns_query).await
                && let Some((_, Some(doc))) = results.into_iter().next()
            {
                let props = doc.properties();
                if let Some(label) = props.get("label").and_then(|v| v.as_text()) {
                    // Update the contact in the list
                    if let Some(contact) = contact_list
                        .iter_mut()
                        .find(|c| c.identity_id == *contact_id)
                    {
                        contact.username = Some(label.to_string());
                    }
                }
            }
        }
    }

    Ok(BackendTaskSuccessResult::DashPayContactsWithInfo(
        contact_list,
    ))
}

pub async fn add_contact(
    _app_context: &Arc<AppContext>,
    _sdk: &Sdk,
    _identity: QualifiedIdentity,
    _contact_username: String,
    _account_label: Option<String>,
) -> Result<BackendTaskSuccessResult, String> {
    // TODO: Steps to implement:
    // 1. Resolve username to identity ID via DPNS
    // 2. Generate encryption keys for this contact relationship
    // 3. Create the contactRequest document with encrypted fields
    // 4. Broadcast the state transition
    Err("Adding contacts via username is not yet implemented. Use the contact request workflow instead.".to_string())
}

pub async fn remove_contact(
    _app_context: &Arc<AppContext>,
    _sdk: &Sdk,
    _identity: QualifiedIdentity,
    _contact_id: Identifier,
) -> Result<BackendTaskSuccessResult, String> {
    // TODO: Implement contact removal
    // This would involve deleting the contactInfo document if it exists
    Err("Contact removal is not yet implemented".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> Identifier {
        Identifier::from_bytes(&[byte; 32]).expect("32 bytes is a valid Identifier")
    }

    #[test]
    fn mutual_contacts_intersect_only_reciprocal_pairs() {
        // Incoming: requests from A, B, C to us.
        // Outgoing: requests from us to B, C, D.
        // Mutual contacts should be {B, C}.
        let incoming = vec![id(0xA1), id(0xB2), id(0xC3)];
        let outgoing = vec![id(0xB2), id(0xC3), id(0xD4)];

        let mutual = find_mutual_contacts(incoming, outgoing);

        assert_eq!(mutual.len(), 2);
        assert!(mutual.contains(&id(0xB2)));
        assert!(mutual.contains(&id(0xC3)));
        assert!(!mutual.contains(&id(0xA1)));
        assert!(!mutual.contains(&id(0xD4)));
    }

    #[test]
    fn mutual_contacts_handles_pagination_across_sets() {
        // Simulate pagination behavior: an outgoing match for one of our incoming
        // requests lives at position 150, well beyond a single fixed page of 100.
        // Once both sets are fully fetched, the intersection still finds it.
        let incoming: Vec<Identifier> = (0..200u32).map(|i| id((i % 256) as u8)).collect();
        let mut outgoing: Vec<Identifier> = (50..250u32).map(|i| id((i % 256) as u8)).collect();
        outgoing.push(id(0xFE));

        let mutual = find_mutual_contacts(incoming.clone(), outgoing);

        // Every incoming id at >= 50 should be matched (the loop wraps mod 256, so
        // the dedup happens via HashSet collection).
        for ident in incoming.iter().skip(50) {
            assert!(mutual.contains(ident), "expected {:?} in mutual set", ident);
        }
        assert!(!mutual.contains(&id(0xFE))); // 0xFE only in outgoing
    }

    #[test]
    fn mutual_contacts_empty_when_no_overlap() {
        let incoming = vec![id(0x01), id(0x02)];
        let outgoing = vec![id(0x03), id(0x04)];

        let mutual = find_mutual_contacts(incoming, outgoing);
        assert!(mutual.is_empty());
    }

    #[test]
    fn mutual_contacts_empty_when_either_side_empty() {
        let incoming: Vec<Identifier> = vec![];
        let outgoing = vec![id(0x01)];
        assert!(find_mutual_contacts(incoming, outgoing).is_empty());

        let incoming = vec![id(0x01)];
        let outgoing: Vec<Identifier> = vec![];
        assert!(find_mutual_contacts(incoming, outgoing).is_empty());
    }

    #[test]
    fn mutual_contacts_dedups_repeated_incoming() {
        // If an identity appears twice in the incoming list (e.g. weird platform
        // state), the result is still a set, so no duplicates leak through.
        let incoming = vec![id(0xAA), id(0xAA), id(0xBB)];
        let outgoing = vec![id(0xAA), id(0xBB)];

        let mutual = find_mutual_contacts(incoming, outgoing);
        assert_eq!(mutual.len(), 2);
    }
}
