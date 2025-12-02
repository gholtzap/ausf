use mongodb::{Client, Collection, Database};
use std::env;

pub struct MongoClient {
    db: Database,
}

impl MongoClient {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let uri = env::var("MONGODB_URI")
            .unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
        let database_name = env::var("MONGODB_DATABASE")
            .unwrap_or_else(|_| "ausf".to_string());

        let client = Client::with_uri_str(&uri).await?;

        client
            .database("admin")
            .run_command(mongodb::bson::doc! { "ping": 1 })
            .await?;

        tracing::info!("Successfully connected to MongoDB at {}", uri);

        let db = client.database(&database_name);

        Ok(Self { db })
    }

    pub fn get_collection<T: Send + Sync>(&self, name: &str) -> Collection<T> {
        self.db.collection(name)
    }
}
