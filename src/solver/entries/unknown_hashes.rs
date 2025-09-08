use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::rngs::ThreadRng;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct UnknownHashesEntry {
    pub hash_1_key: String,
    pub hash_2_key: String,
    pub hash_3_key: String,
    pub hash_4_key: String,
}

#[async_trait]
impl FingerprintEntryBase for UnknownHashesEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        // println!("{:?}", strings);
        let hash_1_key = get_string_at_offset(quick_idx_map, strings, "String", 2)?;
        let hash_2_key = get_string_at_offset(quick_idx_map, strings, "getComputedTextLength", -3)?;
        let hash_3_key = get_string_at_offset(quick_idx_map, strings, "getComputedTextLength", 2)?;
        let hash_4_key = get_string_at_offset(quick_idx_map, strings, "getComputedTextLength", 6)?;

        Ok(Self {
            hash_1_key,
            hash_2_key,
            hash_3_key,
            hash_4_key,
        })
    }


    async fn write_entry(&self, _: &mut TurnstileTaskEntryContext, map: &mut Map<String, Value>) -> Result<usize, Error> {
        map.insert(self.hash_1_key.clone(), Value::String(random_hex(64)));
        map.insert(self.hash_2_key.clone(), Value::String(random_hex(64)));
        map.insert(self.hash_3_key.clone(), Value::String(random_hex(64)));
        map.insert(self.hash_4_key.clone(), Value::String(random_hex(64)));

        Ok(rng().random_range(81..=140))
    }
}

fn random_hex(len: usize) -> String {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    let mut rng = ThreadRng::default();
    let mut ret = String::with_capacity(len);

    for _ in 0..len {
        let idx = rng.random_range(0..16);
        ret.push(HEX_CHARS[idx] as char);
    }

    ret
}