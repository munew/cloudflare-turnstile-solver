use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::{bail, Context, Error};
use async_trait::async_trait;
use num::BigInt;
use rand::{random_range, rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct PerformanceMemoryEntry {
    has_performance_memory_key: String,
    performance_memory_array_key: String,
    content_security_policy_key: String,
    history_replace_state_key: String,
    error_value: String,
    memory_radix: isize,
}

// const JS_HEAP_SIZE_LIMIT: isize = 4294705152; // 4095.75 * 1024 * 1024

#[async_trait]
impl FingerprintEntryBase for PerformanceMemoryEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], values: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {

        // println!("performance memory strings: {:?}", strings);
        let has_performance_memory_key = get_string_at_offset(quick_idx_map, strings, "replaceState##1", 6)?;
        let performance_memory_array_key = get_string_at_offset(quick_idx_map, strings, "map", 1)?;
        let error_value = get_string_at_offset(quick_idx_map, strings, "removeChild", -1)?;
        let content_security_policy_key = get_string_at_offset(quick_idx_map, strings, r#"<html><meta http-equiv="content-security-policy" content="default-src">"#, 1)?;
        let history_replace_state_key = get_string_at_offset(quick_idx_map, strings, "replaceState##1", 2)?;

        let memory_radix_value = values.get(values.iter().position(|k| {
            if let VMEntryValue::String(s) = k && *s == "toString" {
                return true;
            }

            false
        }).context("Failed to find radix")? + 1).context("Failed to get radix")?;

        let memory_radix = match memory_radix_value {
            VMEntryValue::Integer(i) => i,
            _ => bail!("radix is not an integer"),
        };

        Ok(Self {
            history_replace_state_key,
            content_security_policy_key,
            error_value,
            performance_memory_array_key,
            has_performance_memory_key,
            memory_radix: *memory_radix,
        })
    }


    async fn write_entry(&self, _: &mut TurnstileTaskEntryContext, map: &mut Map<String, Value>) -> Result<usize, Error> {
        // dbg!(self);
        
        map.insert(self.has_performance_memory_key.clone(), true.into());
        map.insert(self.performance_memory_array_key.clone(), build_performance_array(self.memory_radix).into());
        map.insert(self.content_security_policy_key.clone(), self.error_value.clone().into());
        map.insert(self.history_replace_state_key.clone(), self.error_value.clone().into());
        Ok(rng().random_range(150..=250))
    }
}

fn num_to_str_radix(num: isize, radix: isize) -> String {
    BigInt::from(num).to_str_radix(radix as u32)
}

fn build_performance_array(radix: isize) -> Vec<String> {
    let mut vec = Vec::new();

    let values: &[isize] = &[
        64755896,
        54688468,
        4294705152,
        64755896,
        54688468,
        4294705152,
        64755896,
        54688468,
        4294705152,
        64755896,
        54688468,
        4294705152,
        63395826,
        24620306,
        4294705152,
        64735218,
        26915434,
        4294705152
    ];

    let noise: usize = random_range(1..30000);
    for v in values {
        if *v == 4294705152 {
            vec.push(num_to_str_radix(*v, radix));
            continue;
        }

        vec.push(num_to_str_radix(*v + (noise as isize), radix));
    }
    

    vec
}