use crate::solver::entries::get_string_at_offset;
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use crate::solver::{entries::FingerprintEntryBase, utils::random_time};
use anyhow::Error;
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct DivRenderTimeEntry {
    pub perf_key: String,
}

#[async_trait]
impl FingerprintEntryBase for DivRenderTimeEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(Self {
            perf_key: get_string_at_offset(quick_idx_map, strings, "appendChild", 3)?,
        })
    }


    async fn write_entry(&self, _: &mut TurnstileTaskEntryContext, map: &mut Map<String, Value>) -> Result<usize, Error> {
        let t = random_time(&mut rand::rng(), 3.0..5.0);

        map.insert(
            self.perf_key.clone(),
            t.into(),
        );

        Ok(t as usize + rng().random_range(12..=24))
    }
}
