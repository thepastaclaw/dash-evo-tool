use crate::database::Database;
use crate::model::wallet::WalletSeedHash;
use rusqlite::{Connection, OptionalExtension, params};

const COMMITMENT_TREE_TABLES: [&str; 4] = [
    "commitment_tree_shards",
    "commitment_tree_cap",
    "commitment_tree_checkpoints",
    "commitment_tree_checkpoint_marks_removed",
];
const COMMITMENT_TREE_META_TABLE: &str = "shielded_commitment_tree_meta";

fn corrupted_blob_length_error(column: &'static str, len: usize) -> rusqlite::Error {
    crate::database::CorruptedBlobError(format!(
        "{column} blob has invalid length {len}, expected 32 bytes"
    ))
    .into()
}

fn blob_to_32_bytes(column: &'static str, bytes: Vec<u8>) -> rusqlite::Result<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(corrupted_blob_length_error(column, bytes.len()));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn commitment_tree_table_exists(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
        [table],
        |row| row.get::<_, i32>(0).map(|count| count > 0),
    )
}

fn clear_commitment_tree_tables_on_connection(conn: &Connection) -> rusqlite::Result<()> {
    for table in COMMITMENT_TREE_TABLES {
        if commitment_tree_table_exists(conn, table)? {
            conn.execute(&format!("DELETE FROM {table}"), [])?;
        }
    }
    Ok(())
}

impl Database {
    /// Create shielded pool tables (v28 migration).
    pub(crate) fn create_shielded_tables(&self, conn: &Connection) -> rusqlite::Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS shielded_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                wallet_seed_hash BLOB NOT NULL,
                note_data BLOB NOT NULL,
                position INTEGER NOT NULL,
                cmx BLOB NOT NULL,
                nullifier BLOB NOT NULL,
                block_height INTEGER NOT NULL,
                is_spent INTEGER NOT NULL DEFAULT 0,
                value INTEGER NOT NULL,
                network TEXT NOT NULL,
                UNIQUE(wallet_seed_hash, nullifier, network),
                FOREIGN KEY (wallet_seed_hash) REFERENCES wallet(seed_hash) ON DELETE CASCADE
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_shielded_notes_wallet_network
             ON shielded_notes (wallet_seed_hash, network)",
            [],
        )?;

        Ok(())
    }

    /// Insert a shielded note into the database.
    pub fn insert_shielded_note(
        &self,
        wallet_seed_hash: &WalletSeedHash,
        note: &InsertShieldedNote<'_>,
    ) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO shielded_notes
             (wallet_seed_hash, note_data, position, cmx, nullifier, block_height, value, network)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                wallet_seed_hash.as_slice(),
                note.note_data,
                note.position as i64,
                note.cmx.as_slice(),
                note.nullifier.as_slice(),
                note.block_height as i64,
                note.value as i64,
                note.network,
            ],
        )?;
        Ok(())
    }

    /// Get all unspent shielded notes for a wallet on a given network.
    pub fn get_unspent_shielded_notes(
        &self,
        wallet_seed_hash: &WalletSeedHash,
        network: &str,
    ) -> rusqlite::Result<Vec<ShieldedNoteRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, note_data, position, cmx, nullifier, block_height, value, is_spent
             FROM shielded_notes
             WHERE wallet_seed_hash = ?1 AND network = ?2 AND is_spent = 0
             ORDER BY position ASC",
        )?;

        let rows = stmt.query_map(params![wallet_seed_hash.as_slice(), network], |row| {
            Ok(ShieldedNoteRow {
                id: row.get(0)?,
                note_data: row.get(1)?,
                position: row.get::<_, i64>(2)? as u64,
                cmx: blob_to_32_bytes("cmx", row.get(3)?)?,
                nullifier: blob_to_32_bytes("nullifier", row.get(4)?)?,
                block_height: row.get::<_, i64>(5)? as u64,
                value: row.get::<_, i64>(6)? as u64,
                is_spent: row.get::<_, i64>(7)? != 0,
            })
        })?;

        rows.collect()
    }

    /// Get all shielded notes (spent and unspent) for a wallet on a given network.
    pub fn get_all_shielded_notes(
        &self,
        wallet_seed_hash: &WalletSeedHash,
        network: &str,
    ) -> rusqlite::Result<Vec<ShieldedNoteRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, note_data, position, cmx, nullifier, block_height, value, is_spent
             FROM shielded_notes
             WHERE wallet_seed_hash = ?1 AND network = ?2
             ORDER BY position ASC",
        )?;

        let rows = stmt.query_map(params![wallet_seed_hash.as_slice(), network], |row| {
            Ok(ShieldedNoteRow {
                id: row.get(0)?,
                note_data: row.get(1)?,
                position: row.get::<_, i64>(2)? as u64,
                cmx: blob_to_32_bytes("cmx", row.get(3)?)?,
                nullifier: blob_to_32_bytes("nullifier", row.get(4)?)?,
                block_height: row.get::<_, i64>(5)? as u64,
                value: row.get::<_, i64>(6)? as u64,
                is_spent: row.get::<_, i64>(7)? != 0,
            })
        })?;

        rows.collect()
    }

    /// Mark a shielded note as spent by its nullifier.
    pub fn mark_shielded_note_spent(
        &self,
        wallet_seed_hash: &WalletSeedHash,
        nullifier: &[u8; 32],
        network: &str,
    ) -> rusqlite::Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE shielded_notes SET is_spent = 1
             WHERE wallet_seed_hash = ?1 AND nullifier = ?2 AND network = ?3",
            params![wallet_seed_hash.as_slice(), nullifier.as_slice(), network],
        )
    }

    /// Delete all shielded notes for a wallet (used by resync).
    pub fn delete_shielded_notes(
        &self,
        wallet_seed_hash: &WalletSeedHash,
        network: &str,
    ) -> rusqlite::Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM shielded_notes WHERE wallet_seed_hash = ?1 AND network = ?2",
            params![wallet_seed_hash.as_slice(), network],
        )
    }

    fn ensure_commitment_tree_meta_table(&self, conn: &Connection) -> rusqlite::Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS shielded_commitment_tree_meta (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 0),
                network TEXT
            )",
            [],
        )?;
        Ok(())
    }

    fn get_commitment_tree_owner(&self, conn: &Connection) -> rusqlite::Result<Option<String>> {
        self.ensure_commitment_tree_meta_table(conn)?;
        conn.query_row(
            &format!("SELECT network FROM {COMMITMENT_TREE_META_TABLE} WHERE singleton = 0"),
            [],
            |row| row.get(0),
        )
        .optional()
    }

    fn set_commitment_tree_owner(&self, conn: &Connection, network: &str) -> rusqlite::Result<()> {
        self.ensure_commitment_tree_meta_table(conn)?;
        conn.execute(
            &format!(
                "INSERT INTO {COMMITMENT_TREE_META_TABLE} (singleton, network)
                 VALUES (0, ?1)
                 ON CONFLICT(singleton) DO UPDATE SET network = excluded.network"
            ),
            [network],
        )?;
        Ok(())
    }

    fn clear_commitment_tree_owner(&self, conn: &Connection) -> rusqlite::Result<()> {
        if commitment_tree_table_exists(conn, COMMITMENT_TREE_META_TABLE)? {
            conn.execute(
                &format!("DELETE FROM {COMMITMENT_TREE_META_TABLE} WHERE singleton = 0"),
                [],
            )?;
        }
        Ok(())
    }

    fn commitment_tree_has_rows(&self, conn: &Connection) -> rusqlite::Result<bool> {
        for table in COMMITMENT_TREE_TABLES {
            if !commitment_tree_table_exists(conn, table)? {
                continue;
            }
            let has_rows = conn.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table} LIMIT 1)"),
                [],
                |row| row.get::<_, i64>(0).map(|exists| exists != 0),
            )?;
            if has_rows {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Ensure the shared commitment tree is bound to the requested network.
    ///
    /// The upstream SQLite store is global, so when switching networks we must
    /// clear stale rows before the tree is reused under a different network.
    pub fn prepare_commitment_tree_tables(&self, network: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        let owner = self.get_commitment_tree_owner(&conn)?;
        if owner.as_deref() == Some(network) {
            return Ok(());
        }

        if self.commitment_tree_has_rows(&conn)? {
            clear_commitment_tree_tables_on_connection(&conn)?;
        }

        self.set_commitment_tree_owner(&conn, network)
    }

    /// Clear commitment tree data only when the shared tree currently belongs
    /// to the requested network.
    ///
    /// Handles fresh installs where grovedb creates these tables lazily —
    /// each DELETE is skipped if the table does not exist yet.
    pub fn clear_commitment_tree_tables(&self, network: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();

        if self.get_commitment_tree_owner(&conn)?.as_deref() != Some(network) {
            return Ok(());
        }

        clear_commitment_tree_tables_on_connection(&conn)?;
        self.clear_commitment_tree_owner(&conn)?;
        Ok(())
    }

    /// Create the shielded_wallet_meta table (v29 migration).
    pub(crate) fn create_shielded_wallet_meta_table(
        &self,
        conn: &Connection,
    ) -> rusqlite::Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS shielded_wallet_meta (
                wallet_seed_hash BLOB NOT NULL,
                network TEXT NOT NULL,
                last_nullifier_sync_height INTEGER NOT NULL DEFAULT 0,
                last_nullifier_sync_timestamp INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (wallet_seed_hash, network),
                FOREIGN KEY (wallet_seed_hash) REFERENCES wallet(seed_hash) ON DELETE CASCADE
            )",
            [],
        )?;
        Ok(())
    }

    /// Migration: Add last_nullifier_sync_timestamp column (v30).
    pub(crate) fn add_nullifier_sync_timestamp_column(
        &self,
        conn: &Connection,
    ) -> rusqlite::Result<()> {
        let table_exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='shielded_wallet_meta'",
            [],
            |row| row.get::<_, i32>(0).map(|count| count > 0),
        )?;

        if table_exists {
            let has_column: bool = conn.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('shielded_wallet_meta') WHERE name='last_nullifier_sync_timestamp'",
                [],
                |row| row.get::<_, i32>(0).map(|count| count > 0),
            )?;

            if !has_column {
                conn.execute(
                    "ALTER TABLE shielded_wallet_meta ADD COLUMN last_nullifier_sync_timestamp INTEGER NOT NULL DEFAULT 0",
                    [],
                )?;
            }
        }

        Ok(())
    }

    /// Get the last nullifier sync height and timestamp for a wallet on a given network.
    pub fn get_nullifier_sync_info(
        &self,
        wallet_seed_hash: &WalletSeedHash,
        network: &str,
    ) -> Result<(u64, u64), String> {
        let conn = self.conn.lock().unwrap();
        let result = conn.query_row(
            "SELECT last_nullifier_sync_height, last_nullifier_sync_timestamp FROM shielded_wallet_meta
             WHERE wallet_seed_hash = ?1 AND network = ?2",
            params![wallet_seed_hash.as_slice(), network],
            |row| {
                let height: i64 = row.get(0)?;
                let timestamp: i64 = row.get(1)?;
                Ok((height as u64, timestamp as u64))
            },
        );
        match result {
            Ok(info) => Ok(info),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok((0, 0)),
            Err(e) => Err(format!("Failed to get nullifier sync info: {e}")),
        }
    }

    /// Set the last nullifier sync height and timestamp for a wallet on a given network.
    pub fn set_nullifier_sync_info(
        &self,
        wallet_seed_hash: &WalletSeedHash,
        network: &str,
        height: u64,
        timestamp: u64,
    ) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO shielded_wallet_meta
             (wallet_seed_hash, network, last_nullifier_sync_height, last_nullifier_sync_timestamp)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                wallet_seed_hash.as_slice(),
                network,
                height as i64,
                timestamp as i64
            ],
        )
        .map_err(|e| format!("Failed to set nullifier sync info: {e}"))?;
        Ok(())
    }

    /// Get total shielded balance (sum of unspent note values) for a wallet.
    pub fn get_shielded_balance(
        &self,
        wallet_seed_hash: &WalletSeedHash,
        network: &str,
    ) -> rusqlite::Result<u64> {
        let conn = self.conn.lock().unwrap();
        let result: i64 = conn.query_row(
            "SELECT COALESCE(SUM(value), 0) FROM shielded_notes
             WHERE wallet_seed_hash = ?1 AND network = ?2 AND is_spent = 0",
            params![wallet_seed_hash.as_slice(), network],
            |row| row.get(0),
        )?;
        Ok(result as u64)
    }
}

/// Parameters for inserting a shielded note.
pub struct InsertShieldedNote<'a> {
    pub note_data: &'a [u8],
    pub position: u64,
    pub cmx: &'a [u8; 32],
    pub nullifier: &'a [u8; 32],
    pub block_height: u64,
    pub value: u64,
    pub network: &'a str,
}

/// Row data for a shielded note from the database.
pub struct ShieldedNoteRow {
    pub id: i64,
    pub note_data: Vec<u8>,
    pub position: u64,
    pub cmx: [u8; 32],
    pub nullifier: [u8; 32],
    pub block_height: u64,
    pub value: u64,
    pub is_spent: bool,
}
