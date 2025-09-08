use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{json, Map, Value};

#[derive(Debug, Clone)]
pub struct StackEntry {
    pub array_key: String,
}

#[async_trait]
impl FingerprintEntryBase for StackEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        // dbg!(&strings);
        let array_key = get_string_at_offset(quick_idx_map, strings, " ", 2)?;

        Ok(Self {
            array_key,
        })
    }


    async fn write_entry(
        &self,
        _: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        map.insert(self.array_key.clone(), json!([]));
        Ok(rng().random_range(10..=20))
    }
}
