use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct PrivateAccessTokenEntry {
    pub pat_status_key: String,
    pub pat_query: String,
}

#[async_trait]
impl FingerprintEntryBase for PrivateAccessTokenEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let pat_status_key = get_string_at_offset(quick_idx_map, strings, "substring", -1)?;
        let pat_query = get_string_at_offset(quick_idx_map, strings, "/cdn-cgi/challenge-platform", 1)?;

        Ok(Self {
            pat_status_key,
            pat_query,
        })
    }


    async fn write_entry(&self, task: &mut TurnstileTaskEntryContext, map: &mut Map<String, Value>) -> Result<usize, Error> {
        if task.referrer.starts_with("https") {
            let t = Instant::now();
            let perf = task.task_client.get_pat(&self.pat_query).await?;
            task.performance.add_entry(perf);
            map.insert(self.pat_status_key.to_string(), "status_401".to_string().into());
            Ok(t.elapsed().as_millis() as usize + rng().random_range(10..=20))
        } else {
            map.insert(self.pat_status_key.to_string(), "I".into());
            Ok(rng().random_range(1..=3))
        }
    }
}
