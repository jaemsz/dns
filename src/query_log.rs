use crate::config::LoggingConfig;
use rusqlite::Connection;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

const CHANNEL_CAPACITY: usize = 10_000;
const BATCH_SIZE: usize = 500;
const BATCH_TIMEOUT_MS: u64 = 100;

#[derive(Debug, Clone, Copy)]
pub enum QueryAction {
    Allowed,
    Blocked,
    Local,
}

impl fmt::Display for QueryAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueryAction::Allowed => write!(f, "allowed"),
            QueryAction::Blocked => write!(f, "blocked"),
            QueryAction::Local => write!(f, "local"),
        }
    }
}

pub struct QueryLogEntry {
    pub ts: u64,
    pub domain: String,
    pub qtype: String,
    pub source_ip: String,
    pub action: QueryAction,
    pub resolved_ip: String,
}

impl QueryLogEntry {
    pub fn new(
        domain: String,
        qtype: String,
        source_ip: String,
        action: QueryAction,
        resolved_ip: String,
    ) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            ts,
            domain,
            qtype,
            source_ip,
            action,
            resolved_ip,
        }
    }
}

/// Non-blocking query logger. Sends entries through a bounded channel to a
/// dedicated writer task that batches INSERTs into SQLite transactions.
#[derive(Clone)]
pub struct QueryLogger {
    tx: mpsc::Sender<QueryLogEntry>,
}

impl QueryLogger {
    /// Open the SQLite database, create tables, spawn the writer and purge tasks.
    pub fn new(config: &LoggingConfig) -> anyhow::Result<Self> {
        let db_path = config.db_path.clone();
        let retention_days = config.retention_days;

        // Open connection and initialize schema
        let conn = open_db(&db_path)?;
        info!(path = %db_path, "Query log database opened");

        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);

        // Spawn the batched writer task
        tokio::task::spawn_blocking(move || {
            writer_loop(conn, rx);
            info!("Query log writer shut down");
        });

        // Spawn the periodic purge task
        let purge_db_path = db_path;
        tokio::spawn(async move {
            purge_loop(&purge_db_path, retention_days).await;
        });

        Ok(Self { tx })
    }

    /// Log a query entry. Non-blocking — drops the entry if the channel is full.
    pub fn log(&self, entry: QueryLogEntry) {
        if let Err(mpsc::error::TrySendError::Full(_)) = self.tx.try_send(entry) {
            warn!("Query log channel full, dropping entry");
        }
    }
}

fn open_db(path: &str) -> anyhow::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA cache_size=-8000;
         PRAGMA busy_timeout=5000;

         CREATE TABLE IF NOT EXISTS query_log (
             id          INTEGER PRIMARY KEY,
             ts          INTEGER NOT NULL,
             domain      TEXT    NOT NULL,
             qtype       TEXT    NOT NULL,
             source_ip   TEXT    NOT NULL,
             action      TEXT    NOT NULL,
             resolved_ip TEXT    NOT NULL DEFAULT ''
         );

         CREATE INDEX IF NOT EXISTS idx_query_log_ts ON query_log(ts);
         CREATE INDEX IF NOT EXISTS idx_query_log_domain ON query_log(domain);",
    )?;
    Ok(conn)
}

/// Drains the channel in batches and writes them in a single transaction.
/// Runs inside `spawn_blocking` since rusqlite is synchronous.
fn writer_loop(conn: Connection, mut rx: mpsc::Receiver<QueryLogEntry>) {
    let mut batch: Vec<QueryLogEntry> = Vec::with_capacity(BATCH_SIZE);

    loop {
        // Block until the first entry arrives (or channel closes)
        match rx.blocking_recv() {
            Some(entry) => batch.push(entry),
            None => {
                // Channel closed — flush remaining and exit
                if !batch.is_empty() {
                    flush_batch(&conn, &batch);
                }
                return;
            }
        }

        // Drain up to BATCH_SIZE more entries without blocking,
        // or until the timeout expires
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(BATCH_TIMEOUT_MS);

        while batch.len() < BATCH_SIZE {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match rx.blocking_recv() {
                Some(entry) => batch.push(entry),
                None => {
                    flush_batch(&conn, &batch);
                    return;
                }
            }
        }

        flush_batch(&conn, &batch);
        batch.clear();
    }
}

fn flush_batch(conn: &Connection, batch: &[QueryLogEntry]) {
    if batch.is_empty() {
        return;
    }
    let result = conn.execute_batch("BEGIN");
    if let Err(e) = result {
        error!("Query log BEGIN failed: {e}");
        return;
    }

    let mut stmt = match conn
        .prepare_cached("INSERT INTO query_log (ts, domain, qtype, source_ip, action, resolved_ip) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")
    {
        Ok(s) => s,
        Err(e) => {
            error!("Query log prepare failed: {e}");
            let _ = conn.execute_batch("ROLLBACK");
            return;
        }
    };

    for entry in batch {
        if let Err(e) = stmt.execute(rusqlite::params![
            entry.ts,
            entry.domain,
            entry.qtype,
            entry.source_ip,
            entry.action.to_string(),
            entry.resolved_ip,
        ]) {
            error!("Query log insert failed: {e}");
        }
    }

    drop(stmt);
    if let Err(e) = conn.execute_batch("COMMIT") {
        error!("Query log COMMIT failed: {e}");
    }
}

/// Runs DELETE every hour to purge entries older than retention_days.
async fn purge_loop(db_path: &str, retention_days: u64) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
    let db_path = db_path.to_string();
    let max_age_secs = retention_days * 86400;

    loop {
        interval.tick().await;

        let path = db_path.clone();
        let result = tokio::task::spawn_blocking(move || {
            let conn = match Connection::open(&path) {
                Ok(c) => c,
                Err(e) => {
                    error!("Query log purge: cannot open db: {e}");
                    return 0usize;
                }
            };
            let cutoff = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                - max_age_secs;

            match conn.execute("DELETE FROM query_log WHERE ts < ?1", rusqlite::params![cutoff]) {
                Ok(deleted) => deleted,
                Err(e) => {
                    error!("Query log purge failed: {e}");
                    0
                }
            }
        })
        .await;

        if let Ok(deleted) = result {
            if deleted > 0 {
                info!(deleted, "Query log purged old entries");
            }
        }
    }
}
