use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct MathEntry {
    pub hash_key: String,
}

#[async_trait]
impl FingerprintEntryBase for MathEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let hash_key = get_string_at_offset(quick_idx_map, strings, "err", -1)?;

        Ok(Self {
            hash_key,
        })
    }


    async fn write_entry(&self, task: &mut TurnstileTaskEntryContext, map: &mut Map<String, Value>) -> Result<usize, Error> {
        map.insert(self.hash_key.clone(), task.fingerprint.math_fingerprint.clone().into());
        Ok(rng().random_range(18..=40))
    }
}
