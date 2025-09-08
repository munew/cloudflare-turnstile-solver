use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::utils::{get_timezone_offset, get_utc_offset_for_timezone_on_dec1};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct TimezoneEntry {
    pub year_999_offset_key: String,
    pub year_1060_offset_key: String,
    pub year_1937_offset_key: String,
    pub year_1945_offset_key: String,
    pub year_1989_offset_key: String,
    pub minutes_diff_utc_key: String,
    pub timezone_offset_key: String,
    pub timezone_name_key: String,
}

#[async_trait]
impl FingerprintEntryBase for TimezoneEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let year_999_offset_key = get_string_at_offset(quick_idx_map, strings, "999", -1)?;
        let year_1060_offset_key = get_string_at_offset(quick_idx_map, strings, "1060", -1)?;
        let year_1937_offset_key = get_string_at_offset(quick_idx_map, strings, "1937", -1)?;
        let year_1945_offset_key = get_string_at_offset(quick_idx_map, strings, "1945", -1)?;
        let year_1989_offset_key = get_string_at_offset(quick_idx_map, strings, "1989", -1)?;
        let minutes_diff_utc_key = get_string_at_offset(quick_idx_map, strings, "1989", 1)?;
        let timezone_offset_key = get_string_at_offset(quick_idx_map, strings, "getTimezoneOffset", -1)?;
        let timezone_name_key = get_string_at_offset(quick_idx_map, strings, "getTimezoneOffset", 1)?;

        Ok(Self {
            year_999_offset_key,
            year_1060_offset_key,
            year_1937_offset_key,
            year_1945_offset_key,
            year_1989_offset_key,
            minutes_diff_utc_key,
            timezone_offset_key,
            timezone_name_key,
        })
    }


    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        let year_999_offset = 0; // I believe Date is broken when it comes to comparing dates under 1000
        let year_1060_offset = get_utc_offset_for_timezone_on_dec1(1060, &task.timezone)?;
        let year_1937_offset = get_utc_offset_for_timezone_on_dec1(1937, &task.timezone)?;
        let year_1945_offset = get_utc_offset_for_timezone_on_dec1(1945, &task.timezone)?;
        let year_1989_offset = get_utc_offset_for_timezone_on_dec1(1989, &task.timezone)?;
        let timezone_offset = get_timezone_offset(&task.timezone)?;

        map.insert(self.year_999_offset_key.to_string(), year_999_offset.into());
        map.insert(
            self.year_1060_offset_key.to_string(),
            year_1060_offset.into(),
        );
        map.insert(
            self.year_1937_offset_key.to_string(),
            year_1937_offset.into(),
        );
        map.insert(
            self.year_1945_offset_key.to_string(),
            year_1945_offset.into(),
        );
        map.insert(
            self.year_1989_offset_key.to_string(),
            year_1989_offset.into(),
        );
        map.insert(
            self.minutes_diff_utc_key.to_string(),
            timezone_offset.into(),
        );
        map.insert(self.timezone_offset_key.to_string(), timezone_offset.into());
        map.insert(
            self.timezone_name_key.to_string(),
            task.timezone.into(),
        );

        Ok(rng().random_range(4..=6))
    }
}
