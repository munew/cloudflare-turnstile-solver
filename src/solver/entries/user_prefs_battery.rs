use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct UserPreferencesAndBatteryEntry {
    pub prefers_dark_mode_key: String,
    pub forced_colors_key: String,
    pub prefers_contrast_key: String,
    pub prefers_reduced_motion_key: String,
    pub has_get_battery_info_key: String,
    pub charging_key: String,
    pub level_key: String,
    pub charging_time_key: String,
    pub discharging_time_key: String,
}

#[async_trait]
impl FingerprintEntryBase for UserPreferencesAndBatteryEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let prefers_dark_mode_key = get_string_at_offset(quick_idx_map, strings, "(prefers-color-scheme: dark)", -2)?;
        let forced_colors_key = get_string_at_offset(quick_idx_map, strings, "(forced-colors: active)", -2)?;
        let prefers_contrast_key = get_string_at_offset(quick_idx_map, strings, "(prefers-contrast: no-preference)", -2)?;
        let prefers_reduced_motion_key = get_string_at_offset(quick_idx_map, strings, "(prefers-reduced-motion: reduce)", -2)?;
        let has_get_battery_info_key = get_string_at_offset(quick_idx_map, strings, "getBattery", 1)?;
        let charging_key = get_string_at_offset(quick_idx_map, strings, "charging", -1)?;
        let level_key = get_string_at_offset(quick_idx_map, strings, "level", -1)?;
        let charging_time_key = get_string_at_offset(quick_idx_map, strings, "chargingTime", 1)?;
        let discharging_time_key = get_string_at_offset(quick_idx_map, strings, "dischargingTime", 1)?;

        Ok(Self {
            prefers_dark_mode_key,
            forced_colors_key,
            prefers_contrast_key,
            prefers_reduced_motion_key,
            has_get_battery_info_key,
            charging_key,
            level_key,
            charging_time_key,
            discharging_time_key,
        })
    }


    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        let fingerprint = &task.fingerprint;

        map.insert(
            self.prefers_dark_mode_key.to_string(),
            fingerprint.user_preferences.dark_mode.into(),
        );
        map.insert(
            self.forced_colors_key.to_string(),
            fingerprint.user_preferences.forced_colors.into(),
        );
        map.insert(
            self.prefers_contrast_key.to_string(),
            fingerprint.user_preferences.prefers_contrast.into(),
        );
        map.insert(
            self.prefers_reduced_motion_key.to_string(),
            fingerprint
                .user_preferences
                .prefers_reduced_motion
                .into(),
        );

        map.insert(
            self.has_get_battery_info_key.to_string(),
            fingerprint
                .user_preferences
                .battery_info
                .is_some()
                .into(),
        );

        if let Some(battery_info) = &fingerprint.user_preferences.battery_info {
            map.insert(
                self.charging_key.to_string(),
                battery_info.charging.into(),
            );

            map.insert(
                self.level_key.to_string(),
                serde_json::to_value(&battery_info.level)?,
            );

            map.insert(
                self.charging_time_key.to_string(),
                battery_info.charging_time.into(),
            );

            map.insert(
                self.discharging_time_key.to_string(),
                battery_info.discharging_time.into(),
            );
        }

        Ok(rng().random_range(3..=10))
    }
}
