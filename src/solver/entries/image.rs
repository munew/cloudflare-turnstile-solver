use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{json, Map, Value};
use std::io::Cursor;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct ImageEntry {
    pub image_path: String,
    pub encrypted_content_key: String,
}

#[async_trait]
impl FingerprintEntryBase for ImageEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let image_path = get_string_at_offset(quick_idx_map, strings, "/cdn-cgi/challenge-platform", 1)?;
        let encrypted_content_key = get_string_at_offset(quick_idx_map, strings, "String", 2)?;

        Ok(Self {
            image_path,
            encrypted_content_key,
        })
    }


    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        let t = Instant::now();

        let (perf, body) = task.task_client.get_image(&self.image_path).await?;
        task.performance.add_entry(perf);
        
        let decoder = png::Decoder::new(Cursor::new(body));
        let image = decoder.read_info()?;
        let image_info = image.info();
        
        let encrypted = task.encryption.encrypt(json!([
            image_info.width.to_string(), // yes to_string calls are done on purpose
            image_info.height.to_string(),
        ]));

        map.insert(self.encrypted_content_key.to_string(), encrypted.into());
        Ok(t.elapsed().as_millis() as usize + rng().random_range(10..=20))
    }
}
