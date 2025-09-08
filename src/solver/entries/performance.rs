use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::performance::{PerformanceEntry, PerformanceMarkEntry};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct PerformanceEntriesEntry {
    entries_key: String,
}

#[async_trait]
impl FingerprintEntryBase for PerformanceEntriesEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let entries_key = get_string_at_offset(quick_idx_map, strings, "first-input", -1)?;
        Ok(Self {
            entries_key,
        })
    }


    async fn write_entry(&self, task: &mut TurnstileTaskEntryContext, map: &mut Map<String, Value>) -> Result<usize, Error> {
        // Turnstile marks performance with c-ray before actually collecting them
        // JS: performance.mark(c_ray);
        task.performance.add_entry(PerformanceEntry::Mark(PerformanceMarkEntry {
            r#type: "m".to_string(),
            name: format!("cp-n-{}", task.challenge_data.c_ray),
        }));

        map.insert(self.entries_key.clone(), task.performance.serialize());
        Ok(rng().random_range(8..=15))
    }
}