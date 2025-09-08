use crate::solver::entries::FingerprintEntryBase;
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::{Context, Error};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use once_cell::sync::Lazy;
use rand::{random_range, rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{json, Map, Value};
use crate::solver::utils::get_timezone_offset;

#[derive(Debug, Clone)]
pub struct BrowserKeysEntry {
    browser_keys_key: String,
    unknown_key_1: String,
    unknown_key_2: String,
}

static ORIG_BROWSER_KEYS: Lazy<Map<String, Value>> = Lazy::new(|| {
    let base = include_str!("browser_keys_base.json");
    serde_json::from_str(base).unwrap()
});

#[async_trait]
impl FingerprintEntryBase for BrowserKeysEntry {
    fn parse(
        quick_idx_map: &FxHashMap<String, usize>,
        strings: &[String],
        _: &[VMEntryValue],
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let content_document_idx = quick_idx_map
            .get("contentDocument##1")
            .context("browser keys entry: could not find contentDocument##1 in strings")?;

        Ok(Self {
            browser_keys_key: strings
                .get(content_document_idx - 3)
                .context("browser keys entry: could not find browser keys key")?
                .to_string(),
            unknown_key_1: strings
                .get(content_document_idx - 2)
                .context("browser keys entry: could not find unknown key 1")?
                .to_string(),
            unknown_key_2: strings
                .get(content_document_idx - 1)
                .context("browser keys entry: could not find unknown key 2")?
                .to_string(),
        })
    }


    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        let keys = task.browser_cf_keys.clone();
        let mut base: Map<String, Value> = ORIG_BROWSER_KEYS.clone();

        let original_keys: Vec<String> = base.keys().cloned().collect();

        let utc: DateTime<Utc> = DateTime::<Utc>::from(*task.solve_start_time);
        let timezone_offset = get_timezone_offset(task.timezone)?;
        let adjusted = utc + Duration::minutes(-timezone_offset);
        let new_ts = adjusted.format("%m/%d/%Y %H:%M:%S").to_string();

        let new_url = task
            .solve_url
            .to_string();

        let mut new_base = Map::with_capacity(base.len());
        for key in original_keys {
            let mut values = base.remove(&key).unwrap();
            
            match key.as_str() {
                "{referrer}" => new_base.insert(new_url.clone(), values),
                "{domain}" => new_base.insert("challenges.cloudflare.com".to_string(), values),
                "{origin}" => new_base.insert("https://challenges.cloudflare.com".to_string(), values),
                "{lastModified}" => new_base.insert(new_ts.clone(), values),
                "{languages}" => new_base.insert(task.fingerprint.language_info.languages.clone().join(","), values),
                "{userAgent}" => new_base.insert(task.fingerprint.user_agent.clone(), values),
                "{appVersion}" => new_base.insert(task.fingerprint.user_agent.clone().replace("Mozilla/5.0", "5.0"), values),
                "{platform}" => new_base.insert(task.fingerprint.platform.clone(), values),
                "{language}" => new_base.insert(task.fingerprint.language_info.language.clone(), values),
                "interactive" => new_base.insert("complete".to_string(), values),
                "0" => {
                    let last = values.as_array_mut().unwrap().last_mut().unwrap();
                    *last = format!("o.{}", keys[0]).into();
                    new_base.insert(key, values);
                    None
                }
                "" => {
                    let arr = values.as_array_mut().unwrap();
                    arr.push(format!("o.{}", keys[1]).into());
                    new_base.insert(key, values);

                    None
                }
                _ => new_base.insert(key.clone(), values),
            };
        }

        let timing = (-random_range(4..15)).to_string();
        new_base.insert(timing.clone(), json!([ format!("o.{}", keys[2]) ]));

        map.insert(self.browser_keys_key.clone(), new_base.into());
        map.insert(
            self.unknown_key_1.clone(),
            json!({
                (self.unknown_key_2.clone()): false
            }),
        );

        Ok(rng().random_range(100..150))
    }
}
