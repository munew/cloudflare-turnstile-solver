use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Clone, Debug)]
pub struct WorkerPerformanceTimingEntry {
    timing_key: String,
}

#[async_trait]
impl FingerprintEntryBase for WorkerPerformanceTimingEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let timing_key = get_string_at_offset(quick_idx_map, strings, "onmessage", 1)?;

        Ok(Self {
            timing_key,
        })
    }


    async fn write_entry(&self, _: &mut TurnstileTaskEntryContext, map: &mut Map<String, Value>) -> Result<usize, Error> {
        map.insert(self.timing_key.clone(), 0.10000000894069672.to_string().into());
        Ok(rng().random_range(10..=25))
    }
}