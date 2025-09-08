use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};
use std::iter::repeat_n;

#[derive(Debug, Clone)]
pub struct EngineBehaviorEntry {
    encrypted_content_key: String,
    append_key: String,
}

#[async_trait]
impl FingerprintEntryBase for EngineBehaviorEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let encrypted_content_key = get_string_at_offset(quick_idx_map, strings, "toString##4", 2)?;
        let append_key = get_string_at_offset(quick_idx_map, strings, "toString##4", -2)?;

        Ok(Self {
            encrypted_content_key: encrypted_content_key.to_string(),
            append_key: append_key.to_string(),
        })
    }


    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        let mut arr: Vec<Value> = Vec::with_capacity(86);

        arr.extend(repeat_n(true.into(), 66));
        arr.push(117.into());
        arr.extend(repeat_n("undefined".into(), 2));
        arr.extend(repeat_n("object".into(), 2));
        arr.push("undefined".into());
        arr.push(false.into());
        arr.push("undefined".into());
        arr.push(true.into());
        arr.push(13.into());
        arr.push(0.into());
        arr.push(1.into());
        arr.push(true.into());
        arr.push(false.into());
        arr.push((-1).into());
        arr.push((-1).into());
        arr.push("[object Undefined]".into());
        arr.push(18.into());
        arr.push(format!("{}611", self.append_key).into());
        arr.push(format!("{}/\\u006d\\u0069\\u0067\\u0075\\u0065\\u006c\\u0077\\u0061\\u0073\\u0068\\u0065\\u0072\\u0065/", self.append_key).into());

        let encrypted = task.encryption.encrypt(arr.into());
        map.insert(self.encrypted_content_key.clone(), encrypted.into());

        Ok(rng().random_range(26..=90))
    }
}
