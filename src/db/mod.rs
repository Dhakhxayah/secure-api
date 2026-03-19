// dotenvy loads our .env file so we can read DATABASE_URL
use dotenvy::dotenv;
use std::env;

// sqlx gives us a connection pool to PostgreSQL
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

// PgPool is a "pool" of database connections
// Instead of opening a new connection for every request (slow),
// a pool keeps several connections open and reuses them (fast)
pub async fn create_pool() -> PgPool {
    // Load .env file
    dotenv().ok();

    // Read the DATABASE_URL from .env
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env file");

    // Create the connection pool
    // max_connections(5) means at most 5 simultaneous DB connections
    PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to PostgreSQL. Is it running?")
}