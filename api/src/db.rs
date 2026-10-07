//! Versioned schema migrations, serialized across instances with an advisory lock.

use sqlx::{Connection, PgConnection, PgPool};

const MIGRATIONS: &[(i32, &str)] = &[
    (1, include_str!("../migrations/001_init.sql")),
    (2, include_str!("../migrations/002_hardening.sql")),
];

const MIGRATION_LOCK_ID: i64 = 727_302;

fn statements(sql: &str) -> Vec<String> {
    let without_comments: String = sql
        .lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    without_comments
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub async fn migrate(db: &PgPool) -> anyhow::Result<()> {
    let mut conn = db.acquire().await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(MIGRATION_LOCK_ID)
        .execute(&mut *conn)
        .await?;
    let result = run(&mut conn).await;
    let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(MIGRATION_LOCK_ID)
        .execute(&mut *conn)
        .await;
    result
}

async fn run(conn: &mut PgConnection) -> anyhow::Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version integer PRIMARY KEY,
            applied_at timestamptz NOT NULL DEFAULT now()
        )",
    )
    .execute(&mut *conn)
    .await?;

    for (version, sql) in MIGRATIONS {
        let applied: Option<i32> = sqlx::query_scalar("SELECT version FROM schema_migrations WHERE version = $1")
            .bind(*version)
            .fetch_optional(&mut *conn)
            .await?;
        if applied.is_some() {
            continue;
        }
        let mut tx = conn.begin().await?;
        for stmt in statements(sql) {
            sqlx::query(&stmt).execute(&mut *tx).await?;
        }
        sqlx::query("INSERT INTO schema_migrations (version) VALUES ($1)")
            .bind(*version)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        tracing::info!(version, "applied database migration");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_split_into_statements_without_stray_fragments() {
        for (_, sql) in MIGRATIONS {
            let stmts = statements(sql);
            assert!(!stmts.is_empty());
            for s in stmts {
                assert!(!s.contains(';'));
                assert!(s.split_whitespace().next().is_some());
            }
        }
    }
}
