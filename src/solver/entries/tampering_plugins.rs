use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::{Context, Error};
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct TamperingAndPluginsEntry {
    pub encrypted_key: String,
    pub values: Vec<Value>,
}

fn get_by_pattern(pattern: &[&str], strings: &[String]) -> Option<usize> {
    let mut vec_index = 0;
    for (i, item) in strings.iter().enumerate() {
        if *item == pattern[vec_index] {
            vec_index += 1;
            if vec_index == pattern.len() {
                return Some(i);
            }
        } else {
            vec_index = 0;
        }
    }
    None
}

#[async_trait]
impl FingerprintEntryBase for TamperingAndPluginsEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let mut values: Vec<Value> = Vec::new();

        let first_elem =
            get_string_at_offset(quick_idx_map, strings, "groupCollapsed", 2)?;
        // first_elem[2] = '_';
        values.push(first_elem.into());

        let name_getter = &strings[get_by_pattern(&["defineProperty", "name", "get"], strings)
            .context(
                "tampering and plugins entry: could not find by pattern (defineProperty, name, get)",
            )? + 1];

        let message_getter = &strings[get_by_pattern(
            &["defineProperty", "message", "get"],
            strings,
        )
            .context(
                "tampering and plugins entry: could not find by pattern (defineProperty, message, get)",
            )? + 1];

        let stack_getter = &strings[get_by_pattern(&["defineProperty", "stack", "get"], strings)
            .context(
                "tampering and plugins entry: could not find by pattern (defineProperty, stack, get)",
            )? + 1];

        let value1 = get_string_at_offset(quick_idx_map, strings, "toString##9", 1)?;
        let value1_1 = get_string_at_offset(quick_idx_map, strings, "toString##9", 4)?;

        let value2 = get_string_at_offset(quick_idx_map, strings, "toString##10", 1)?;
        let value2_1 = get_string_at_offset(quick_idx_map, strings, "toString##10", 4)?;

        let value3 = get_string_at_offset(quick_idx_map, strings, "createElement", 3)?;

        let plugin_array_name = get_string_at_offset(quick_idx_map, strings, "plugins##1", -3)?;
        let mimetype_array_name = get_string_at_offset(quick_idx_map, strings, "MimeType", -2)?;

        let repeaters: Vec<String> = (14..=22)
            .map(|i| {
                let key = format!("length##{i}");
                get_string_at_offset(quick_idx_map, strings, &key, 1)
            })
            .collect::<Result<_, _>>()?;
        let remove_name = get_string_at_offset(quick_idx_map, strings, "remove", -1)?;

        values.extend(
            [
                "function count() { [native code] }",
                "function count() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function count() { [native code] }",
                "function count() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function countReset() { [native code] }",
                "function countReset() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function countReset() { [native code] }",
                "function countReset() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function debug() { [native code] }",
                "function debug() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function debug() { [native code] }",
                "function debug() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function dir() { [native code] }",
                "function dir() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function dir() { [native code] }",
                "function dir() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function dirxml() { [native code] }",
                "function dirxml() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function dirxml() { [native code] }",
                "function dirxml() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function error() { [native code] }",
                "function error() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function error() { [native code] }",
                "function error() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function info() { [native code] }",
                "function info() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function info() { [native code] }",
                "function info() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function log() { [native code] }",
                "function log() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function log() { [native code] }",
                "function log() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function table() { [native code] }",
                "function table() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function table() { [native code] }",
                "function table() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function trace() { [native code] }",
                "function trace() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function trace() { [native code] }",
                "function trace() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function warn() { [native code] }",
                "function warn() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "function warn() { [native code] }",
                "function warn() { [native code] }",
                "TypeError Cyclic __proto__ value",
                "[object console]",
                "[object console]",
                "[object console]",
                "[object console]",
            ]
                .into_iter()
                .map(|v| v.into())
                .collect::<Vec<Value>>(),
        );

        values.extend(
            [
                name_getter.clone(),
                message_getter.clone(),
                stack_getter.clone(),
                value1.clone(),
                value2.clone(),
                value3.clone(),
            ]
                .into_iter()
                .map(|v| v.into())
                .collect::<Vec<Value>>(),
        );

        values.push(21.into());
        values.push(0.into());
        values.push(format!("{plugin_array_name}PDF ViewerChrome PDF ViewerChromium PDF ViewerMicrosoft Edge PDF ViewerWebKit built-in PDF").into());
        values.push(0.into());
        values.push(format!("{mimetype_array_name}pdfpdf").into());

        values.push(value1_1.clone().into());
        values.push(value1_1.into());
        values.push(value2_1.clone().into());
        values.push(value2_1.into());

        for id in repeaters {
            values.extend([name_getter.clone().into(), id.clone().into()]);
            values.extend([message_getter.clone().into(), id.clone().into()]);
            values.extend([name_getter.clone().into(), id.clone().into()]);
            values.extend([message_getter.clone().into(), id.clone().into()]);
        }
        values.extend([name_getter.clone().into(), remove_name.clone().into()]);
        values.extend([message_getter.clone().into(), remove_name.clone().into()]);
        values.extend([stack_getter.clone().into(), remove_name.clone().into()]);

        let encrypted_key = get_string_at_offset(quick_idx_map, strings, "concat", 1)?;

        Ok(Self {
            encrypted_key,
            values,
        })
    }


    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        let encrypted_values = task.encryption.encrypt(self.values.clone().into());
        map.insert(self.encrypted_key.clone(), encrypted_values.into());

        Ok(rng().random_range(110..=200))
    }
}
