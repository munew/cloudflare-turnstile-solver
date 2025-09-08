use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::{anyhow, bail, Context};
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct BrowserDataEntry {
    pub message_result_key: String,
    pub message_object_key: String,
    pub platform_key: String,
    pub languages_key: String,
    pub hardware_concurrency_key: String,
    pub device_memory_key: String,
    pub user_agent_key: String,

    message_order: Vec<String>,
}

#[async_trait]
impl FingerprintEntryBase for BrowserDataEntry {
    fn parse(
        quick_idx_map: &FxHashMap<String, usize>,
        strings: &[String],
        _: &[VMEntryValue],
    ) -> Result<Self, anyhow::Error>
    where
        Self: Sized,
    {
        let message_object_key = get_string_at_offset(quick_idx_map, strings, "terminate", 2)?;

        let js_code = strings
            .iter()
            .find(|k| k.contains("postMessage({"))
            .context("browser data entry: could not find postMessage string")?
            .replace("postMessage({ ", "")
            .replace("});", "");

        let mut values = Vec::new();

        for e in js_code.split(",") {
            let mut split = e.split(":");
            let mapped_key = split
                .next()
                .context("browser data entry: expected mapped key")?
                .trim();
            let key = split.next().unwrap().trim();

            values.push((key.to_string(), mapped_key.to_string()));
        }

        let mut platform_key = None;
        let mut languages_key = None;
        let mut hardware_concurrency_key = None;
        let mut device_memory_key = None;
        let mut user_agent_key = None;

        let mut message_order = Vec::new();

        for (key, mapped_key) in values {
            message_order.push(key.to_string());

            match key.as_str() {
                "navigator.platform" => platform_key = Some(mapped_key.to_string()),
                "navigator.languages" => languages_key = Some(mapped_key.to_string()),
                "navigator.hardwareConcurrency" => {
                    hardware_concurrency_key = Some(mapped_key.to_string())
                }
                "navigator.deviceMemory" => device_memory_key = Some(mapped_key.to_string()),
                "navigator.userAgent" => user_agent_key = Some(mapped_key.to_string()),
                _ => bail!("Unknown browser data key: {key}"),
            };
        }

        let message_result_key = get_string_at_offset(quick_idx_map, strings, "terminate", 1)?;

        Ok(Self {
            message_result_key,
            message_object_key,
            platform_key: platform_key.ok_or_else(|| anyhow!("could not find platform key"))?,
            languages_key: languages_key.ok_or_else(|| anyhow!("could not find languages key"))?,
            hardware_concurrency_key: hardware_concurrency_key
                .ok_or_else(|| anyhow!("could not find hardware concurrency key"))?,
            device_memory_key: device_memory_key
                .ok_or_else(|| anyhow!("could not find device memory key"))?,
            user_agent_key: user_agent_key
                .ok_or_else(|| anyhow!("could not find user agent key"))?,
            message_order,
        })
    }
    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, anyhow::Error> {
        let fp = &task.fingerprint;
        map.insert(self.message_result_key.clone(), 0.into());
        let mut message = Map::new();

        for entry in &self.message_order {
            match entry.as_str() {
                "navigator.platform" => {
                    message.insert(self.platform_key.clone(), fp.platform.clone().into())
                }
                "navigator.languages" => {
                    message.insert(self.languages_key.clone(), fp.language_info.languages.clone().into())
                }
                "navigator.hardwareConcurrency" => message.insert(
                    self.hardware_concurrency_key.clone(),
                    fp.hardware_concurrency.into(),
                ),
                "navigator.deviceMemory" => {
                    message.insert(self.device_memory_key.clone(), fp.device_memory.into())
                }
                "navigator.userAgent" => {
                    message.insert(self.user_agent_key.clone(), fp.user_agent.clone().into())
                }
                _ => return Err(anyhow!("Unknown browser data key: {}", entry)),
            };
        }

        map.insert(self.message_object_key.clone(), message.into());
        Ok(rng().random_range(7..=20))
    }
}
