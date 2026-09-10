// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! MySQL Database Editor — detection, connection, and query execution

use mysql_async::prelude::*;
use mysql_async::{Opts, OptsBuilder, Pool, Row, Value};
use serde::{Deserialize, Serialize};
use tracing::error;

/// Supported database types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum DbType {
    #[default]
    Mysql,
    Postgres,
}


/// Connection parameters sent from the frontend
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConnParams {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: String,
    /// Optional: which database to USE
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub db_type: DbType,
}

fn default_port() -> u16 {
    3306
}

/// Common Unix socket paths for MySQL/MariaDB
const SOCKET_PATHS: &[&str] = &[
    "/var/run/mysqld/mysqld.sock",
    "/run/mysqld/mysqld.sock",
    "/tmp/mysql.sock",
    "/var/lib/mysql/mysql.sock",
    "/var/run/mysql/mysql.sock",
];

/// Check if the host is a localhost address
fn is_localhost(host: &str) -> bool {
    let h = host.trim().to_lowercase();
    h == "localhost" || h == "127.0.0.1" || h == "::1"
}

/// Find a MySQL Unix socket on the local machine
fn find_socket() -> Option<&'static str> {
    SOCKET_PATHS.iter().copied().find(|p| std::path::Path::new(p).exists())
}

impl ConnParams {
    /// Build opts for TCP connection
    fn to_tcp_opts(&self) -> Opts {
        let mut builder = OptsBuilder::default()
            .ip_or_hostname(&self.host)
            .tcp_port(self.port)
            .user(Some(&self.user))
            .pass(Some(&self.password));
        if let Some(db) = &self.database
            && !db.is_empty() {
                builder = builder.db_name(Some(db));
            }
        builder.into()
    }

    /// Build opts for Unix socket connection
    fn to_socket_opts(&self, socket_path: &str) -> Opts {
        let mut builder = OptsBuilder::default()
            .socket(Some(socket_path))
            .user(Some(&self.user))
            .pass(Some(&self.password));
        if let Some(db) = &self.database
            && !db.is_empty() {
                builder = builder.db_name(Some(db));
            }
        builder.into()
    }
}

/// Connection timeout in seconds for all MySQL operations
const CONN_TIMEOUT_SECS: u64 = 5;

/// Extract a detailed, human-readable message from a mysql_async error.
/// The default Display impl can emit just "ERROR" for server errors;
/// this digs into the variant to pull out the code + message.
fn detailed_mysql_error(e: &mysql_async::Error) -> String {
    match e {
        mysql_async::Error::Server(server_err) => {
            format!("MySQL error {}: {} (SQLSTATE {})",
                server_err.code, server_err.message, server_err.state)
        }
        mysql_async::Error::Io(io_err) => {
            format!("I/O error: {}", io_err)
        }
        other => {
            // Use Debug for a more detailed fallback than Display
            let display = format!("{}", other);
            if display.len() <= 10 {
                // If Display is too terse (e.g. just "ERROR"), use Debug
                format!("{:?}", other)
            } else {
                display
            }
        }
    }
}

/// Create a pool and get a connection with a timeout.
/// For localhost connections, tries Unix socket first, then falls back to TCP.
/// Returns (Pool, Conn) so callers can disconnect the pool when done.
async fn get_conn_with_timeout(
    params: &ConnParams,
) -> Result<(Pool, mysql_async::Conn), String> {
    // For localhost: try Unix socket first (most Linux MySQL installs default to socket-only)
    if is_localhost(&params.host)
        && let Some(sock) = find_socket() {

            let pool = Pool::new(params.to_socket_opts(sock));
            let conn_result = tokio::time::timeout(
                std::time::Duration::from_secs(CONN_TIMEOUT_SECS),
                pool.get_conn(),
            )
            .await;
            match conn_result {
                Ok(Ok(c)) => {

                    return Ok((pool, c));
                }
                Ok(Err(_e)) => {

                    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), pool.disconnect()).await;
                }
                Err(_) => {

                    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), pool.disconnect()).await;
                }
            }
        }

    // TCP connection (used for remote hosts, or as fallback for localhost)
    let pool = Pool::new(params.to_tcp_opts());
    let conn_result = tokio::time::timeout(
        std::time::Duration::from_secs(CONN_TIMEOUT_SECS),
        pool.get_conn(),
    )
    .await;
    match conn_result {
        Ok(Ok(c)) => {

            Ok((pool, c))
        }
        Ok(Err(e)) => {
            let detail = detailed_mysql_error(&e);
            error!("MySQL connection failed ({}:{}): {}", params.host, params.port, detail);
            Err(format!("Connection to {}:{} failed: {}", params.host, params.port, detail))
        }
        Err(_) => {
            error!("MySQL connection timed out ({}:{})", params.host, params.port);
            Err(format!(
                "Connection to {}:{} timed out after {} seconds",
                params.host, params.port, CONN_TIMEOUT_SECS
            ))
        }
    }
}

/// Detect if MySQL server or client binaries are installed on this machine
pub fn detect_mysql() -> serde_json::Value {
    let paths_to_check = [
        "/usr/bin/mysql",
        "/usr/sbin/mysqld",
        "/usr/bin/mariadb",
        "/usr/sbin/mariadbd",
        "/usr/local/bin/mysql",
        "/usr/local/sbin/mysqld",
    ];

    let mut found = Vec::new();
    for path in &paths_to_check {
        if std::path::Path::new(path).exists() {
            found.push(*path);
        }
    }

    // Also check PATH via `which`
    for bin in &["mysql", "mysqld", "mariadb", "mariadbd"] {
        if let Ok(output) = std::process::Command::new("which").arg(bin).output()
            && output.status.success() {
                let p = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !found.contains(&p.as_str()) {
                    found.push(Box::leak(p.into_boxed_str()));
                }
            }
    }

    // Try to get version if mysql client is available
    let version = std::process::Command::new("mysql")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        });

    // Check if mysqld service is running
    let service_running = std::process::Command::new("systemctl")
        .args(["is-active", "mysql"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false)
        || std::process::Command::new("systemctl")
            .args(["is-active", "mariadb"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
            .unwrap_or(false);

    serde_json::json!({
        "installed": !found.is_empty(),
        "binaries": found,
        "version": version,
        "service_running": service_running,
    })
}

/// Test a MySQL connection — returns the server version string on success
/// Uses a timeout to prevent the UI from hanging on unreachable hosts.
pub async fn test_connection(params: &ConnParams) -> Result<String, String> {

    let (pool, mut conn) = get_conn_with_timeout(params).await?;


    let version: Option<String> = conn
        .query_first("SELECT VERSION()")
        .await
        .map_err(|e| format!("Connected but query failed: {}", detailed_mysql_error(&e)))?;


    // Don't let disconnect hang — fire and forget with a short timeout
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), pool.disconnect()).await;

    Ok(version.unwrap_or_else(|| "unknown".into()))
}

/// List all databases
pub async fn list_databases(params: &ConnParams) -> Result<Vec<String>, String> {
    let (pool, mut conn) = get_conn_with_timeout(params).await?;

    let databases: Vec<String> = conn
        .query("SHOW DATABASES")
        .await
        .map_err(|e| format!("SHOW DATABASES failed: {}", detailed_mysql_error(&e)))?;

    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), pool.disconnect()).await;
    Ok(databases)
}

/// List tables in a specific database
pub async fn list_tables(params: &ConnParams, database: &str) -> Result<Vec<serde_json::Value>, String> {
    reject_unsafe_identifier(database, "database")?;
    let mut p = params.clone();
    p.database = Some(database.to_string());

    let (pool, mut conn) = get_conn_with_timeout(&p).await?;

    // Get table names and types (parameterized to prevent SQL injection)
    let rows: Vec<Row> = conn
        .exec(
            "SELECT TABLE_NAME, TABLE_TYPE, TABLE_ROWS, DATA_LENGTH \
             FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME",
            (database,)
        )
        .await
        .map_err(|e| format!("Tables query failed: {}", detailed_mysql_error(&e)))?;

    let mut tables = Vec::new();
    for row in rows {
        let name: String = row.get(0).unwrap_or_default();
        let table_type: String = row.get(1).unwrap_or_default();
        let row_count: Option<u64> = row.get(2);
        let data_length: Option<u64> = row.get(3);

        tables.push(serde_json::json!({
            "name": name,
            "type": table_type,
            "rows": row_count,
            "data_length": data_length,
        }));
    }

    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), pool.disconnect()).await;
    Ok(tables)
}

/// Get table structure (columns, types, keys)
pub async fn table_structure(
    params: &ConnParams,
    database: &str,
    table: &str,
) -> Result<Vec<serde_json::Value>, String> {
    reject_unsafe_identifier(database, "database")?;
    reject_unsafe_identifier(table, "table")?;
    let mut p = params.clone();
    p.database = Some(database.to_string());

    let (pool, mut conn) = get_conn_with_timeout(&p).await?;

    let rows: Vec<Row> = conn
        .exec(
            "SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY, COLUMN_DEFAULT, EXTRA \
             FROM information_schema.COLUMNS \
             WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? \
             ORDER BY ORDINAL_POSITION",
            (database, table)
        )
        .await
        .map_err(|e| format!("Structure query failed: {}", detailed_mysql_error(&e)))?;

    let mut columns = Vec::new();
    for row in rows {
        let name: String = row.get(0).unwrap_or_default();
        let col_type: String = row.get(1).unwrap_or_default();
        let nullable: String = row.get(2).unwrap_or_default();
        let key: String = row.get(3).unwrap_or_default();
        let default: Option<String> = row.get(4);
        let extra: String = row.get(5).unwrap_or_default();

        columns.push(serde_json::json!({
            "name": name,
            "type": col_type,
            "nullable": nullable == "YES",
            "key": key,
            "default": default,
            "extra": extra,
        }));
    }

    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), pool.disconnect()).await;
    Ok(columns)
}

/// Full MySQL string-literal escape — handles every byte sequence
/// that can break out of a single-quoted string. The previous version
/// only handled `\` and `'`, missing null bytes, control characters,
/// and Ctrl-Z (which Windows mysql clients treat as EOF). Per
/// mysql_real_escape_string semantics.
fn mysql_escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for ch in s.chars() {
        match ch {
            '\0' => out.push_str("\\0"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '"' => out.push_str("\\\""),
            '\x1a' => out.push_str("\\Z"),
            other => out.push(other),
        }
    }
    out
}

/// Reject identifiers that don't look like real MySQL identifiers.
/// Backtick-quoting in the queries below handles SQL semantics, but a
/// crafted identifier with a null byte or control character can still
/// confuse the C-mysql client at the transport layer (truncation, log
/// injection). MySQL's own limit is 64 chars; we cap at 128 to allow
/// some quoted-edge-case headroom while still bounding the input.
fn reject_unsafe_identifier(name: &str, kind: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("{} name is empty", kind));
    }
    if name.len() > 128 {
        return Err(format!("{} name too long ({} chars, max 128)", kind, name.len()));
    }
    if name.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(format!("{} name contains control characters", kind));
    }
    Ok(())
}

/// Get paginated table data
pub async fn table_data(
    params: &ConnParams,
    database: &str,
    table: &str,
    page: u64,
    page_size: u64,
    order_by: Option<&str>,
    order_dir: Option<&str>,
) -> Result<serde_json::Value, String> {
    // Validate identifiers BEFORE opening a connection — cheaper to
    // fail fast and avoids partial state.
    reject_unsafe_identifier(database, "database")?;
    reject_unsafe_identifier(table, "table")?;
    if let Some(col) = order_by {
        reject_unsafe_identifier(col, "order_by column")?;
    }
    // Cap pagination so a crafted request can't cause a multi-GB
    // result set to be built in memory.
    if page_size == 0 || page_size > 10_000 {
        return Err(format!("page_size {} out of range (1..10000)", page_size));
    }

    let mut p = params.clone();
    p.database = Some(database.to_string());

    let (pool, mut conn) = get_conn_with_timeout(&p).await?;

    // Sanitize table name (backtick-quote it). Combined with the
    // identifier validation above, this is the textbook MySQL pattern
    // for safe identifier interpolation.
    let safe_table = format!("`{}`.`{}`",
        database.replace('`', "``"),
        table.replace('`', "``")
    );

    // Get total row count
    let count_row: Option<u64> = conn
        .query_first(format!("SELECT COUNT(*) FROM {}", safe_table))
        .await
        .map_err(|e| format!("Count query failed: {}", detailed_mysql_error(&e)))?;
    let total_rows = count_row.unwrap_or(0);

    // Get column names (parameterized to prevent SQL injection)
    let col_rows: Vec<Row> = conn
        .exec(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS \
             WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? \
             ORDER BY ORDINAL_POSITION",
            (database, table)
        )
        .await
        .map_err(|e| format!("Column query failed: {}", detailed_mysql_error(&e)))?;

    let columns: Vec<String> = col_rows.iter().map(|r| r.get::<String, _>(0).unwrap_or_default()).collect();

    // Get data page
    let offset = page * page_size;
    let order_clause = if let Some(col) = order_by {
        let safe_col = format!("`{}`", col.replace('`', "``"));
        let dir = match order_dir { Some("desc") | Some("DESC") => "DESC", _ => "ASC" };
        format!(" ORDER BY {} {}", safe_col, dir)
    } else { String::new() };
    let data_rows: Vec<Row> = conn
        .query(format!(
            "SELECT * FROM {}{} LIMIT {} OFFSET {}",
            safe_table, order_clause, page_size, offset
        ))
        .await
        .map_err(|e| format!("Data query failed: {}", detailed_mysql_error(&e)))?;

    let rows = rows_to_json(&data_rows, &columns);

    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), pool.disconnect()).await;

    Ok(serde_json::json!({
        "columns": columns,
        "rows": rows,
        "total_rows": total_rows,
        "page": page,
        "page_size": page_size,
        "total_pages": total_rows.div_ceil(page_size),
    }))
}

/// Execute an arbitrary SQL query
pub async fn execute_query(
    params: &ConnParams,
    database: &str,
    query: &str,
) -> Result<serde_json::Value, String> {
    let mut p = params.clone();
    if !database.is_empty() {
        p.database = Some(database.to_string());
    }

    let (pool, mut conn) = get_conn_with_timeout(&p).await?;

    // Determine if it's a SELECT-like query (returns rows) or a modification
    let trimmed = query.trim_start().to_uppercase();
    let is_select = trimmed.starts_with("SELECT")
        || trimmed.starts_with("SHOW")
        || trimmed.starts_with("DESCRIBE")
        || trimmed.starts_with("DESC ")
        || trimmed.starts_with("EXPLAIN");

    if is_select {
        let rows: Vec<Row> = conn
            .query(query)
            .await
            .map_err(|e| format!("Query error: {}", detailed_mysql_error(&e)))?;

        // Extract column names from the first row
        let columns: Vec<String> = if let Some(first) = rows.first() {
            first.columns_ref().iter().map(|c| c.name_str().to_string()).collect()
        } else {
            Vec::new()
        };

        let json_rows = rows_to_json(&rows, &columns);

        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), pool.disconnect()).await;

        Ok(serde_json::json!({
            "type": "resultset",
            "columns": columns,
            "rows": json_rows,
            "row_count": json_rows.len(),
        }))
    } else {
        let result = conn
            .query_iter(query)
            .await
            .map_err(|e| format!("Query error: {}", detailed_mysql_error(&e)))?;

        let affected = result.affected_rows();
        let last_insert_id = result.last_insert_id();

        // Drop the result to release the connection
        drop(result);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), pool.disconnect()).await;

        Ok(serde_json::json!({
            "type": "modification",
            "affected_rows": affected,
            "last_insert_id": last_insert_id,
            "message": format!("{} row(s) affected", affected),
        }))
    }
}

/// Dump a database to SQL text.
/// If `include_data` is true, includes INSERT statements with row data.
pub async fn dump_database(params: &ConnParams, database: &str, include_data: bool) -> Result<String, String> {
    reject_unsafe_identifier(database, "database")?;
    let mut p = params.clone();
    p.database = Some(database.to_string());
    let (pool, mut conn) = get_conn_with_timeout(&p).await?;

    let mut sql = String::new();
    sql.push_str("-- MySQL dump generated by WolfStack\n");
    sql.push_str(&format!("-- Database: {}\n", database));
    sql.push_str(&format!("-- Date: {}\n\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
    sql.push_str(&format!("CREATE DATABASE IF NOT EXISTS `{}`;\n", database.replace('`', "``")));
    sql.push_str(&format!("USE `{}`;\n\n", database.replace('`', "``")));

    // Get all tables (parameterized to prevent SQL injection)
    let tables: Vec<String> = conn
        .exec(
            "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME",
            (database,)
        )
        .await
        .map_err(|e| format!("Failed to list tables: {}", detailed_mysql_error(&e)))?;

    for table in &tables {
        // SHOW CREATE TABLE for the DDL
        let create_row: Option<Row> = conn
            .query_first(format!("SHOW CREATE TABLE `{}`.`{}`",
                database.replace('`', "``"),
                table.replace('`', "``")))
            .await
            .map_err(|e| format!("SHOW CREATE TABLE failed for {}: {}", table, detailed_mysql_error(&e)))?;

        if let Some(row) = create_row {
            let create_stmt: String = row.get(1).unwrap_or_default();
            sql.push_str(&format!("DROP TABLE IF EXISTS `{}`;\n", table.replace('`', "``")));
            sql.push_str(&create_stmt);
            sql.push_str(";\n\n");
        }

        // Data dump
        if include_data {
            let rows: Vec<Row> = conn
                .query(format!("SELECT * FROM `{}`.`{}`",
                    database.replace('`', "``"),
                    table.replace('`', "``")))
                .await
                .map_err(|e| format!("SELECT failed for {}: {}", table, detailed_mysql_error(&e)))?;

            if !rows.is_empty() {
                // Get column names
                let col_names: Vec<String> = rows[0].columns_ref().iter()
                    .map(|c| format!("`{}`", c.name_str()))
                    .collect();

                let col_header = col_names.join(", ");

                for row in &rows {
                    let mut values = Vec::new();
                    for i in 0..row.len() {
                        let val: Option<String> = row.get(i);
                        match val {
                            Some(v) => values.push(format!("'{}'", mysql_escape_string(&v))),
                            None => values.push("NULL".to_string()),
                        }
                    }
                    sql.push_str(&format!("INSERT INTO `{}` ({}) VALUES ({});\n",
                        table.replace('`', "``"),
                        col_header,
                        values.join(", ")));
                }
                sql.push('\n');
            }
        }
    }

    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), pool.disconnect()).await;
    Ok(sql)
}

/// Convert mysql_async Rows to JSON arrays
fn rows_to_json(rows: &[Row], columns: &[String]) -> Vec<Vec<serde_json::Value>> {
    rows.iter()
        .map(|row| {
            (0..columns.len())
                .map(|i| {
                    match row.as_ref(i) {
                        Some(Value::NULL) | None => serde_json::Value::Null,
                        Some(Value::Int(v)) => serde_json::json!(*v),
                        Some(Value::UInt(v)) => serde_json::json!(*v),
                        Some(Value::Float(v)) => serde_json::json!(*v),
                        Some(Value::Double(v)) => serde_json::json!(*v),
                        Some(Value::Bytes(b)) => {
                            // Try UTF-8 string first, fall back to hex for binary data
                            match String::from_utf8(b.clone()) {
                                Ok(s) => serde_json::Value::String(s),
                                Err(_) => serde_json::Value::String(format!("0x{}", hex::encode(b))),
                            }
                        }
                        Some(Value::Date(y, m, d, h, mi, s, _us)) => {
                            serde_json::Value::String(format!(
                                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                                y, m, d, h, mi, s
                            ))
                        }
                        Some(Value::Time(neg, d, h, m, s, _us)) => {
                            let sign = if *neg { "-" } else { "" };
                            if *d > 0 {
                                serde_json::Value::String(format!(
                                    "{}{} {:02}:{:02}:{:02}",
                                    sign, d, h, m, s
                                ))
                            } else {
                                serde_json::Value::String(format!(
                                    "{}{:02}:{:02}:{:02}",
                                    sign, h, m, s
                                ))
                            }
                        }
                    }
                })
                .collect()
        })
        .collect()
}

/// Detect MySQL/MariaDB instances running inside Docker and LXC containers
pub fn detect_mysql_containers() -> Vec<serde_json::Value> {
    let mut results = Vec::new();

    // ── Docker containers ──
    if let Ok(output) = std::process::Command::new("docker")
        .args(["ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}", "--no-trunc"])
        .output()
        && output.status.success() {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                if line.is_empty() { continue; }
                let parts: Vec<&str> = line.split('\t').collect();
                let name = parts.first().unwrap_or(&"").to_string();
                let image = parts.get(1).unwrap_or(&"").to_string();
                let ports_str = parts.get(2).unwrap_or(&"").to_string();

                let image_lower = image.to_lowercase();
                if !image_lower.contains("mysql") && !image_lower.contains("mariadb") {
                    continue;
                }

                // Try to find the published host port for 3306
                let mut host_port: u16 = 3306;
                for port_mapping in ports_str.split(", ") {
                    // Format: "0.0.0.0:3307->3306/tcp" or ":::3307->3306/tcp"
                    if port_mapping.contains("->3306/")
                        && let Some(arrow_pos) = port_mapping.find("->") {
                            let before = &port_mapping[..arrow_pos];
                            if let Some(colon_pos) = before.rfind(':')
                                && let Ok(p) = before[colon_pos + 1..].parse::<u16>() {
                                    host_port = p;
                                }
                        }
                }

                // Get container IP address
                let ip = std::process::Command::new("docker")
                    .args(["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", &name])
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();

                // Use localhost if there's a published port mapping, else use the container IP
                let host = if ports_str.contains("->3306/") {
                    "127.0.0.1".to_string()
                } else if !ip.is_empty() {
                    ip
                } else {
                    "127.0.0.1".to_string()
                };

                results.push(serde_json::json!({
                    "name": name,
                    "image": image,
                    "runtime": "docker",
                    "host": host,
                    "port": host_port,
                }));
            }
        }

    // ── LXC containers ──
    if let Ok(output) = std::process::Command::new("lxc-ls")
        .args(["-f", "-F", "NAME,STATE"])
        .output()
        && output.status.success() {
            for line in String::from_utf8_lossy(&output.stdout).lines().skip(1) {
                if line.is_empty() { continue; }
                let parts: Vec<&str> = line.split_whitespace().collect();
                let name = parts.first().unwrap_or(&"").to_string();
                let state = parts.get(1).unwrap_or(&"STOPPED").to_lowercase();
                if state != "running" { continue; }

                // Check if mysqld is running inside the container
                let mysql_check = std::process::Command::new("lxc-attach")
                    .args(["-n", &name, "--", "pgrep", "-x", "mysqld"])
                    .output();
                let mariadb_check = std::process::Command::new("lxc-attach")
                    .args(["-n", &name, "--", "pgrep", "-x", "mariadbd"])
                    .output();

                let has_mysql = mysql_check.map(|o| o.status.success()).unwrap_or(false)
                    || mariadb_check.map(|o| o.status.success()).unwrap_or(false);

                if !has_mysql { continue; }

                // Get the container's IP
                let ip = std::process::Command::new("lxc-info")
                    .args(["-n", &name, "-iH"])
                    .output()
                    .ok()
                    .map(|o| {
                        String::from_utf8_lossy(&o.stdout)
                            .lines()
                            .find(|l| !l.contains(':')) // skip IPv6
                            .unwrap_or("")
                            .trim()
                            .to_string()
                    })
                    .unwrap_or_default();

                if ip.is_empty() { continue; }

                results.push(serde_json::json!({
                    "name": name,
                    "image": "mysql (lxc)",
                    "runtime": "lxc",
                    "host": ip,
                    "port": 3306,
                }));
            }
        }

    // ── WolfNet IPs — scan for MySQL on port 3306 ──
    let wolfnet_ips = scan_wolfnet_mysql();
    let existing_hosts: std::collections::HashSet<String> = results.iter()
        .filter_map(|r| r.get("host").and_then(|h| h.as_str()).map(|s| s.to_string()))
        .collect();
    for (ip, hostname) in wolfnet_ips {
        if !existing_hosts.contains(&ip) {
            results.push(serde_json::json!({
                "name": if hostname.is_empty() { ip.clone() } else { hostname },
                "image": "mysql (wolfnet)",
                "runtime": "wolfnet",
                "host": ip,
                "port": 3306,
            }));
        }
    }

    results
}

/// Scan WolfNet IPs for MySQL on port 3306
fn scan_wolfnet_mysql() -> Vec<(String, String)> {
    use std::net::{TcpStream, SocketAddr};

    // The real WolfNet network, so a /16's other third octets are scanned too.
    let net = match crate::containers::wolfnet_network() {
        Some(n) => n,
        None => return vec![],
    };

    // Get all IPs with routes in the WolfNet range
    let output = match std::process::Command::new("ip")
        .args(["route", "show"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return vec![],
    };

    let mut ips_to_scan: Vec<String> = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let ip = match line.split_whitespace().next() {
            Some(ip) if !ip.contains('/') && net.contains(ip) => ip,
            _ => continue,
        };
        if !ips_to_scan.contains(&ip.to_string()) {
            ips_to_scan.push(ip.to_string());
        }
    }

    // Also scan .wolfnet/ip files in /var/lib/lxc/*/
    if let Ok(entries) = std::fs::read_dir("/var/lib/lxc") {
        for entry in entries.flatten() {
            let ip_file = entry.path().join(".wolfnet/ip");
            if let Ok(ip) = std::fs::read_to_string(&ip_file) {
                let ip = ip.trim().to_string();
                if !ip.is_empty() && !ips_to_scan.contains(&ip) {
                    ips_to_scan.push(ip);
                }
            }
        }
    }

    // Scan in parallel with 1-second connect timeout
    std::thread::scope(|s| {
        let handles: Vec<_> = ips_to_scan.iter().map(|ip| {
            let ip = ip.clone();
            s.spawn(move || {
                let addr: SocketAddr = match crate::netaddr::host_port(&ip, 3306).parse() {
                    Ok(a) => a,
                    Err(_) => return None,
                };
                match TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(1)) {
                    Ok(_) => {
                        // Try reverse DNS or hostname lookup
                        let hostname = resolve_wolfnet_hostname(&ip);
                        Some((ip, hostname))
                    }
                    Err(_) => None,
                }
            })
        }).collect();

        handles.into_iter()
            .filter_map(|h| h.join().ok().flatten())
            .collect()
    })
}

/// Try to resolve a WolfNet IP to a container hostname
fn resolve_wolfnet_hostname(ip: &str) -> String {
    // Check LXC containers for matching WolfNet IP
    if let Ok(entries) = std::fs::read_dir("/var/lib/lxc") {
        for entry in entries.flatten() {
            let ip_file = entry.path().join(".wolfnet/ip");
            if let Ok(stored_ip) = std::fs::read_to_string(&ip_file)
                && stored_ip.trim() == ip {
                    let name = entry.file_name().to_string_lossy().to_string();
                    // Try to get hostname from config
                    let config = entry.path().join("config");
                    if let Ok(content) = std::fs::read_to_string(&config) {
                        for line in content.lines() {
                            if line.trim().starts_with("lxc.uts.name")
                                && let Some(h) = line.split('=').nth(1) {
                                    return h.trim().to_string();
                                }
                        }
                    }
                    // Proxmox: try pct config
                    if let Ok(out) = std::process::Command::new("pct")
                        .args(["config", &name])
                        .output()
                    {
                        for line in String::from_utf8_lossy(&out.stdout).lines() {
                            if line.trim().starts_with("hostname:")
                                && let Some(h) = line.split(':').nth(1) {
                                    return h.trim().to_string();
                                }
                        }
                    }
                    return name;
                }
        }
    }
    String::new()
}

// ═══════════════════════════════════════════════════════════════════════════
// PostgreSQL Support
// ═══════════════════════════════════════════════════════════════════════════

/// Test a PostgreSQL connection
pub async fn pg_test_connection(params: &ConnParams) -> Result<String, String> {
    let cfg = pg_config(params);
    let (client, connection) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        cfg.connect(tokio_postgres::NoTls)
    ).await
        .map_err(|_| "Connection timed out (5s)".to_string())?
        .map_err(|e| format!("PostgreSQL connection failed: {}", e))?;

    tokio::spawn(async move { let _ = connection.await; });

    let row = client.query_one("SELECT version()", &[]).await
        .map_err(|e| format!("Query failed: {}", e))?;
    let version: String = row.get(0);
    Ok(version)
}

/// List PostgreSQL databases
pub async fn pg_list_databases(params: &ConnParams) -> Result<Vec<String>, String> {
    let client = pg_connect(params).await?;
    let rows = client.query(
        "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname", &[]
    ).await.map_err(|e| format!("Failed to list databases: {}", e))?;

    Ok(rows.iter().map(|r| { let name: String = r.get(0); name }).collect())
}

/// List PostgreSQL tables and views
pub async fn pg_list_tables(params: &ConnParams, database: &str) -> Result<Vec<serde_json::Value>, String> {
    let mut p = params.clone();
    p.database = Some(database.to_string());
    let client = pg_connect(&p).await?;

    let rows = client.query(
        "SELECT table_name, table_type,
         (SELECT n_live_tup FROM pg_stat_user_tables s WHERE s.relname = t.table_name LIMIT 1) as row_est,
         pg_total_relation_size(quote_ident(table_schema) || '.' || quote_ident(table_name)) as size_bytes
         FROM information_schema.tables t
         WHERE table_schema = 'public'
         ORDER BY table_name",
        &[]
    ).await.map_err(|e| format!("Tables query failed: {}", e))?;

    let mut tables = Vec::new();
    for row in &rows {
        let name: String = row.get(0);
        let table_type: String = row.get(1);
        let row_count: Option<i64> = row.try_get(2).ok();
        let data_length: Option<i64> = row.try_get(3).ok();

        tables.push(serde_json::json!({
            "name": name,
            "type": table_type,
            "rows": row_count.map(|r| r as u64),
            "data_length": data_length.map(|d| d as u64),
        }));
    }
    Ok(tables)
}

/// Get PostgreSQL table structure
pub async fn pg_table_structure(params: &ConnParams, database: &str, table: &str) -> Result<serde_json::Value, String> {
    let mut p = params.clone();
    p.database = Some(database.to_string());
    let client = pg_connect(&p).await?;

    // Columns
    let cols = client.query(
        "SELECT column_name, data_type, character_maximum_length, is_nullable,
                column_default, ordinal_position
         FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = $1
         ORDER BY ordinal_position", &[&table]
    ).await.map_err(|e| format!("Column query failed: {}", e))?;

    let columns: Vec<serde_json::Value> = cols.iter().map(|r| {
        let name: String = r.get(0);
        let dtype: String = r.get(1);
        let max_len: Option<i32> = r.try_get(2).ok();
        let nullable: String = r.get(3);
        let default: Option<String> = r.try_get(4).ok();
        serde_json::json!({
            "field": name,
            "type": if let Some(len) = max_len { format!("{}({})", dtype, len) } else { dtype },
            "null": nullable,
            "default": default,
            "key": "",
            "extra": "",
        })
    }).collect();

    // Indexes
    let idx = client.query(
        "SELECT indexname, indexdef FROM pg_indexes
         WHERE tablename = $1 AND schemaname = 'public'
         ORDER BY indexname", &[&table]
    ).await.map_err(|e| format!("Index query failed: {}", e))?;

    let indexes: Vec<serde_json::Value> = idx.iter().map(|r| {
        let name: String = r.get(0);
        let def: String = r.get(1);
        let unique = def.to_lowercase().contains("unique");
        serde_json::json!({
            "key_name": name,
            "column_name": def,
            "non_unique": if unique { 0 } else { 1 },
            "index_type": if def.to_lowercase().contains("btree") { "BTREE" } else { "OTHER" },
        })
    }).collect();

    Ok(serde_json::json!({ "columns": columns, "indexes": indexes, "triggers": [] }))
}

/// Get PostgreSQL table data (paginated)
pub async fn pg_table_data(params: &ConnParams, database: &str, table: &str, page: u32, page_size: u32, order_by: Option<&str>, order_dir: Option<&str>) -> Result<serde_json::Value, String> {
    // Validate identifiers via the shared allowlist before connecting.
    // Previous version used a brittle denylist that rejected legitimate
    // table names with hyphens AND missed null-byte / control-char
    // attacks. Allowlisting via reject_unsafe_identifier is safer.
    reject_unsafe_identifier(database, "database")?;
    reject_unsafe_identifier(table, "table")?;
    if let Some(col) = order_by {
        reject_unsafe_identifier(col, "order_by column")?;
    }
    if page_size == 0 || page_size > 10_000 {
        return Err(format!("page_size {} out of range (1..10000)", page_size));
    }

    let mut p = params.clone();
    p.database = Some(database.to_string());
    let client = pg_connect(&p).await?;

    let offset = page * page_size;
    // Quote the identifier with double-quote-doubling — Postgres parses
    // "" inside quoted identifiers as a literal ". Same trick as MySQL
    // backticks, just different quote char.
    let safe_table = format!("\"{}\"", table.replace('"', "\"\""));
    let count_query = format!("SELECT COUNT(*) FROM {}", safe_table);
    let total: i64 = client.query_one(&count_query, &[]).await
        .map_err(|e| format!("Count failed: {}", e))?
        .get(0);

    let order_clause = if let Some(col) = order_by {
        let safe_col = format!("\"{}\"", col.replace('"', "\"\""));
        let dir = match order_dir { Some("desc") | Some("DESC") => "DESC", _ => "ASC" };
        format!(" ORDER BY {} {}", safe_col, dir)
    } else { String::new() };
    let data_query = format!("SELECT * FROM {}{} LIMIT {} OFFSET {}", safe_table, order_clause, page_size, offset);
    let rows = client.query(&data_query, &[]).await
        .map_err(|e| format!("Data query failed: {}", e))?;

    let columns: Vec<String> = if rows.is_empty() {
        vec![]
    } else {
        rows[0].columns().iter().map(|c| c.name().to_string()).collect()
    };

    let data: Vec<Vec<serde_json::Value>> = rows.iter().map(|row| {
        columns.iter().enumerate().map(|(i, _)| pg_value_to_json(row, i)).collect()
    }).collect();

    Ok(serde_json::json!({
        "columns": columns,
        "rows": data,
        "total_rows": total,
        "page": page,
        "page_size": page_size,
    }))
}

/// Execute a PostgreSQL query
pub async fn pg_execute_query(params: &ConnParams, database: &str, query: &str) -> Result<serde_json::Value, String> {
    let mut p = params.clone();
    p.database = Some(database.to_string());
    let client = pg_connect(&p).await?;

    let query_upper = query.trim().to_uppercase();
    if query_upper.starts_with("SELECT") || query_upper.starts_with("SHOW") || query_upper.starts_with("EXPLAIN") || query_upper.starts_with("WITH") {
        let rows = client.query(query, &[]).await
            .map_err(|e| format!("Query failed: {}", e))?;

        let columns: Vec<String> = if rows.is_empty() {
            vec![]
        } else {
            rows[0].columns().iter().map(|c| c.name().to_string()).collect()
        };

        let data: Vec<Vec<serde_json::Value>> = rows.iter().map(|row| {
            columns.iter().enumerate().map(|(i, _)| pg_value_to_json(row, i)).collect()
        }).collect();

        Ok(serde_json::json!({
            "columns": columns,
            "rows": data,
            "row_count": data.len(),
        }))
    } else {
        let affected = client.execute(query, &[]).await
            .map_err(|e| format!("Execute failed: {}", e))?;
        Ok(serde_json::json!({
            "columns": ["affected_rows"],
            "rows": [[affected]],
            "row_count": 1,
            "affected_rows": affected,
        }))
    }
}

/// Detect PostgreSQL installation
#[allow(dead_code)]
pub fn detect_postgres() -> serde_json::Value {
    let installed = std::process::Command::new("which").arg("psql")
        .output().map(|o| o.status.success()).unwrap_or(false)
        || std::path::Path::new("/usr/bin/psql").exists();

    let running = std::process::Command::new("systemctl")
        .args(["is-active", "postgresql"])
        .output().map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false);

    let version = std::process::Command::new("psql").arg("--version")
        .output().ok()
        .and_then(|o| if o.status.success() {
            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
        } else { None });

    serde_json::json!({
        "installed": installed,
        "service_running": running,
        "version": version,
    })
}

// ─── PostgreSQL helpers ─────────────────────────────────────────────────────

// Build a libpq config via the typed builder rather than string
// interpolation. The previous format!() concatenation let a `host` (or
// password) value like `localhost sslmode=disable passfile=/root/.pgpass`
// inject extra libpq key/value tokens — a connection-string injection
// that could redirect the connection or change its security parameters.
// Config setters treat each value as opaque, so no injection is possible.
fn pg_config(params: &ConnParams) -> tokio_postgres::Config {
    let db = params.database.as_deref().unwrap_or("postgres");
    let mut cfg = tokio_postgres::Config::new();
    cfg.host(&params.host)
        .port(params.port)
        .user(&params.user)
        .password(params.password.as_str())
        .dbname(db)
        .connect_timeout(std::time::Duration::from_secs(5));
    cfg
}

async fn pg_connect(params: &ConnParams) -> Result<tokio_postgres::Client, String> {
    let cfg = pg_config(params);
    let (client, connection) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        cfg.connect(tokio_postgres::NoTls)
    ).await
        .map_err(|_| "Connection timed out (5s)".to_string())?
        .map_err(|e| format!("PostgreSQL connection failed: {}", e))?;

    tokio::spawn(async move { let _ = connection.await; });
    Ok(client)
}

fn pg_value_to_json(row: &tokio_postgres::Row, idx: usize) -> serde_json::Value {
    // Try common types — PostgreSQL has many, handle the most common ones
    if let Ok(v) = row.try_get::<_, Option<String>>(idx) {
        return v.map(serde_json::Value::String).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<_, Option<i64>>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<_, Option<i32>>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<_, Option<f64>>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<_, Option<bool>>(idx) {
        return v.map(|b| serde_json::json!(b)).unwrap_or(serde_json::Value::Null);
    }
    // Fallback: try to get as string representation
    serde_json::Value::Null
}
