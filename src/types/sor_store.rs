use crate::clients::mongodb::MongoClient;
use crate::types::storage::StoredSorContext;
use mongodb::Collection;
use std::sync::Arc;

pub struct SorStore {
    collection: Collection<StoredSorContext>,
}

impl SorStore {
    pub fn new(mongo_client: Arc<MongoClient>) -> Self {
        let collection = mongo_client.get_collection("sor_contexts");
        Self { collection }
    }

    pub async fn insert(
        &self,
        context: StoredSorContext,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.collection.insert_one(context).await?;
        Ok(())
    }

    pub async fn get(
        &self,
        supi: &str,
    ) -> Result<Option<StoredSorContext>, Box<dyn std::error::Error + Send + Sync>> {
        let filter = mongodb::bson::doc! { "_id": supi };
        let result = self.collection.find_one(filter).await?;
        Ok(result)
    }

    pub async fn update_counter(
        &self,
        supi: &str,
        new_counter: u16,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let filter = mongodb::bson::doc! { "_id": supi };
        let update = mongodb::bson::doc! { "$set": { "counter_sor": new_counter as i32 } };
        self.collection.update_one(filter, update).await?;
        Ok(())
    }

    pub async fn delete(
        &self,
        supi: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let filter = mongodb::bson::doc! { "_id": supi };
        self.collection.delete_one(filter).await?;
        Ok(())
    }
}
