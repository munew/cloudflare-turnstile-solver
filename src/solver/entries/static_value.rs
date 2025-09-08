use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct StaticValueEntry {
    pub key: String,
    pub value: String,
}

#[async_trait]
impl FingerprintEntryBase for StaticValueEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let key = get_string_at_offset(quick_idx_map, strings, "length", 1)?;
        let value = get_string_at_offset(quick_idx_map, strings, "length", 2)?;

        Ok(Self {
            key,
            value,
        })
    }


    async fn write_entry(
        &self,
        _: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        map.insert(self.key.clone(), self.value.clone().into());
        Ok(1)
    }
}
