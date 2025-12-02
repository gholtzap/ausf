use crate::clients::mongodb::MongoClient;
use crate::types::storage::StoredAuthContext;
use mongodb::Collection;
use std::sync::Arc;

pub struct AuthStore {
    collection: Collection<StoredAuthContext>,
}

impl AuthStore {
    pub fn new(mongo_client: Arc<MongoClient>) -> Self {
        let collection = mongo_client.get_collection("auth_contexts");
        Self { collection }
    }

    pub async fn insert(
        &self,
        _auth_ctx_id: String,
        context: StoredAuthContext,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.collection.insert_one(context).await?;
        Ok(())
    }

    pub async fn get(
        &self,
        auth_ctx_id: &str,
    ) -> Result<Option<StoredAuthContext>, Box<dyn std::error::Error + Send + Sync>> {
        let filter = mongodb::bson::doc! { "_id": auth_ctx_id };
        let result = self.collection.find_one(filter).await?;
        Ok(result)
    }

    pub async fn delete(
        &self,
        auth_ctx_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let filter = mongodb::bson::doc! { "_id": auth_ctx_id };
        self.collection.delete_one(filter).await?;
        Ok(())
    }

    pub async fn delete_by_supi(
        &self,
        supi: &str,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let filter = mongodb::bson::doc! { "supi": supi };
        let result = self.collection.delete_many(filter).await?;
        Ok(result.deleted_count)
    }
}
