use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{json, Map, Value};

#[derive(Debug, Clone)]
pub struct UserAgentDataEntry {
    pub encrypted_entropy_key: String,
    pub user_agent_data_missing_value: String,
}

#[async_trait]
impl FingerprintEntryBase for UserAgentDataEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let encrypted_entropy_key = get_string_at_offset(quick_idx_map, strings, "getHighEntropyValues", 1)?;
        let user_agent_data_missing_value = get_string_at_offset(quick_idx_map, strings, "getHighEntropyValues", 2)?;

        Ok(Self {
            encrypted_entropy_key,
            user_agent_data_missing_value,
        })
    }


    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        if let Some(user_agent_data) = &task.fingerprint.user_agent_data {
            let encrypted_entropy = task.encryption.encrypt(json!([user_agent_data]));

            map.insert(self.encrypted_entropy_key.clone(), encrypted_entropy.into());
            return Ok(rng().random_range(41..=55));
        }

        map.insert(self.encrypted_entropy_key.clone(), self.user_agent_data_missing_value.clone().into());
        Ok(rng().random_range(2..=8))
    }
}
