use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct WebGLNativeFunctionChecksEntry {
    pub encrypted_content_key: String,
    pub is_native_function_value: String,
}

#[async_trait]
impl FingerprintEntryBase for WebGLNativeFunctionChecksEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let encrypted_content_key = get_string_at_offset(quick_idx_map, strings, "readPixels##3", 1)?;
        let is_native_function_value = get_string_at_offset(quick_idx_map, strings, "test", 2)?;

        Ok(Self {
            encrypted_content_key,
            is_native_function_value,
        })
    }


    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        let mut arr = Vec::new();
        for _ in 0..150 {
            arr.push(self.is_native_function_value.clone());
        }

        let serialized: Value = arr.into();
        let encrypted = task.encryption.encrypt(serialized);
        map.insert(self.encrypted_content_key.to_string(), encrypted.into());

        Ok(rng().random_range(50..=70))
    }
}
