use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{json, Map, Value};

#[derive(Debug, Clone)]
pub struct LanguageEntry {
    pub language_key: String,
    pub languages_key: String,
    pub languages_2_key: String,
    pub solve_language_key: String,
    pub formatted_timezone_key: String,
    pub formatted_language_key: String,
    pub formatted_list_key: String,
    pub formatted_notation_key: String,
}

#[async_trait]
impl FingerprintEntryBase for LanguageEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let language_key = get_string_at_offset(quick_idx_map, strings, "language", -2)?;
        let languages_key = get_string_at_offset(quick_idx_map, strings, "languages", -2)?;
        let languages_2_key = get_string_at_offset(quick_idx_map, strings, "languages", 1)?;
        let solve_language_key = get_string_at_offset(quick_idx_map, strings, "languages", 2)?;
        let formatted_timezone_key = get_string_at_offset(quick_idx_map, strings, "format", 1)?;
        let formatted_language_key = get_string_at_offset(quick_idx_map, strings, "eo-UA", 1)?;
        let formatted_list_key = get_string_at_offset(quick_idx_map, strings, "notation", -3)?;
        let formatted_notation_key = get_string_at_offset(quick_idx_map, strings, "NumberFormat", 2)?;

        Ok(Self {
            language_key,
            languages_key,
            languages_2_key,
            solve_language_key,
            formatted_timezone_key,
            formatted_language_key,
            formatted_list_key,
            formatted_notation_key,
        })
    }


    async fn write_entry(&self, task: &mut TurnstileTaskEntryContext, map: &mut Map<String, Value>) -> Result<usize, Error> {
        map.insert(
            self.language_key.to_string(),
            task.fingerprint.language_info.language.clone().into(),
        );
        map.insert(
            self.languages_key.to_string(),
            task.fingerprint.language_info.languages.clone().into(),
        );
        map.insert(
            self.languages_2_key.to_string(),
            json!([ Value::String(task.fingerprint.language_info.language.clone()) ]),
        );
        map.insert(
            self.solve_language_key.to_string(),
            task.solve_language.to_string().into(),
        );
        map.insert(
            self.formatted_timezone_key.to_string(),
            task.fingerprint
                .language_info
                .formatted_timezone
                .clone()
                .into(),
        );
        map.insert(
            self.formatted_language_key.to_string(),
            task.fingerprint
                .language_info
                .formatted_language
                .clone()
                .into(),
        );
        map.insert(
            self.formatted_list_key.to_string(),
            task.fingerprint.language_info.formatted_list.clone().into(),
        );
        map.insert(
            self.formatted_notation_key.to_string(),
            task.fingerprint
                .language_info
                .formatted_notation
                .clone()
                .into(),
        );

        Ok(rng().random_range(8..30))
    }
}