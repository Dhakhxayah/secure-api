use redis::AsyncCommands;

pub struct AnomalyDetector;

impl AnomalyDetector {
    pub async fn record_bad_request(redis: &redis::Client, ip: &str) -> bool {
        let mut conn = match redis.get_async_connection().await {
            Ok(c) => c,
            Err(_) => return false,
        };
        let key = format!("anomaly:400:{}", ip);
        let count: i64 = conn.incr(&key, 1).await.unwrap_or(0);
        if count == 1 {
            let _: () = conn.expire(&key, 300).await.unwrap_or(());
        }
        if count >= 10 {
            Self::ban_ip(redis, ip, 3600).await;
            return true;
        }
        false
    }

    pub async fn ban_ip(redis: &redis::Client, ip: &str, duration_secs: usize) {
        let mut conn = match redis.get_async_connection().await {
            Ok(c) => c,
            Err(_) => return,
        };
        let key = format!("banned:{}", ip);
        let _: () = conn.set_ex(&key, "banned", duration_secs as u64).await.unwrap_or(());
        tracing::warn!("IP {} has been auto-banned for {} seconds", ip, duration_secs);
    }

    pub async fn is_banned(redis: &redis::Client, ip: &str) -> bool {
        let mut conn = match redis.get_async_connection().await {
            Ok(c) => c,
            Err(_) => return false,
        };
        let key = format!("banned:{}", ip);
        let result: Option<String> = conn.get(&key).await.unwrap_or(None);
        result.is_some()
    }
    #[allow(dead_code)]
    pub async fn record_failed_auth(redis: &redis::Client, ip: &str) -> i64 {
        let mut conn = match redis.get_async_connection().await {
            Ok(c) => c,
            Err(_) => return 0,
        };
        let key = format!("anomaly:auth_fail:{}", ip);
        let count: i64 = conn.incr(&key, 1).await.unwrap_or(0);
        if count == 1 {
            let _: () = conn.expire(&key, 300).await.unwrap_or(());
        }
        if count >= 20 {
            Self::ban_ip(redis, ip, 3600).await;
        }
        count
    }

    pub async fn get_ban_ttl(redis: &redis::Client, ip: &str) -> i64 {
        let mut conn = match redis.get_async_connection().await {
            Ok(c) => c,
            Err(_) => return 0,
        };
        let key = format!("banned:{}", ip);
        let ttl: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .unwrap_or(0);
        ttl
    }
}