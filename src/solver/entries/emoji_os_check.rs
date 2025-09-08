use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct EmojiOsCheckEntry {
    pub key: String,
    pub matches_value: String,
    pub no_matches_value: String,
}

#[async_trait]
impl FingerprintEntryBase for EmojiOsCheckEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let key = get_string_at_offset(quick_idx_map, strings, "chl-exc", -3)?;
        let matches_value = get_string_at_offset(quick_idx_map, strings, "data", 1)?;
        let no_matches_value = get_string_at_offset(quick_idx_map, strings, "length", 1)?;

        Ok(Self {
            key,
            matches_value,
            no_matches_value,
        })
    }


    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        if task.fingerprint.emoji_check_matches {
            map.insert(self.key.to_string(), self.matches_value.to_string().into());
        } else {
            map.insert(
                self.key.to_string(),
                self.no_matches_value.to_string().into(),
            );
        }

        Ok(rng().random_range(2..=8))
    }
}
