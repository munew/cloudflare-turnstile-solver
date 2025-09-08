use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{json, Map, Value};

#[derive(Debug, Clone)]
pub struct SeleniumEntry {
    pub plugins_key: String,
    pub ht_atrs_key: String,
    pub attributes_key: String,
    pub comments_key: String,
}

#[async_trait]
impl FingerprintEntryBase for SeleniumEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        // println!("selenium strings: {:?}", strings);
        let plugins_key = get_string_at_offset(quick_idx_map, strings, "plugins", 3)?;
        let ht_atrs_key = get_string_at_offset(quick_idx_map, strings, "body##1", -2)?;
        let attributes_key = get_string_at_offset(quick_idx_map, strings, "body##1", -1)?;
        let comments_key = get_string_at_offset(quick_idx_map, strings, "body##1", 1)?;

        Ok(Self {
            plugins_key,
            ht_atrs_key,
            attributes_key,
            comments_key,
        })
    }


    async fn write_entry(&self, _: &mut TurnstileTaskEntryContext, map: &mut Map<String, Value>) -> Result<usize, Error> {
        map.insert(self.plugins_key.clone(), "2".into());
        map.insert(self.ht_atrs_key.clone(), json!([]));
        map.insert(self.attributes_key.clone(), json!([]));
        map.insert(self.comments_key.clone(), false.into());

        Ok(rng().random_range(2..=10))
    }
}