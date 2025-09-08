use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Clone, Debug)]
pub struct HTMLRenderEntry {
    encrypted_content_key: String,
}

#[async_trait]
impl FingerprintEntryBase for HTMLRenderEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let encrypted_content_key = get_string_at_offset(quick_idx_map, strings, "removeChild", 1)?;

        Ok(Self {
            encrypted_content_key
        })
    }


    async fn write_entry(&self, task: &mut TurnstileTaskEntryContext, map: &mut Map<String, Value>) -> Result<usize, Error> {
        let encrypted = task.encryption.encrypt(task.fingerprint.html_bounds.clone());
        map.insert(self.encrypted_content_key.clone(), encrypted.into());
        Ok(rng().random_range(60..=90))
    }
}