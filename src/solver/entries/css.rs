use crate::solver::entries::FingerprintEntryBase;
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::{Context, Error};
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct CssEntry {
    pub css_value: String,
    pub css_key: String,
    pub hash_key: String,
}

#[async_trait]
impl FingerprintEntryBase for CssEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let lower_bound_idx = quick_idx_map
            .get("|")
            .context("css entry: could not find | string index")?;
        let upper_bound_idx = quick_idx_map
            .get("cssRules##1")
            .context("css entry: could not find cssRules##1 string index")?;

        let strings_list = &strings[*lower_bound_idx..*upper_bound_idx];
        let (mut css_value, mut css_key) = (String::new(), String::new());

        strings_list.iter().for_each(|s| {
            if s.starts_with(".") {
                css_value = s.clone();
            } else if (s.len() == 5 || s.len() == 6) && s != "length" {
                css_key = s.clone();
            }
        });

        let substring_idx = quick_idx_map
            .get("substring")
            .context("css entry: could not find substring string index")?;
        Ok(Self {
            css_value,
            css_key,
            hash_key: strings
                .get(substring_idx - 1)
                .context("css entry: could not find hash key")?
                .to_string(),
        })
    }


    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        map.insert(
            self.css_key.clone(),
            format!(
                "{} {{ background-image: url(\"/cdn-cgi/challenge-platform/h/{}/cmg/1\"); \
         background-position: -1px -1px; background-repeat: no-repeat; }}1",
                self.css_value, task.task_client.get_branch(),
            )
                .into(),
        );

        map.insert(
            self.hash_key.clone(),
            "6b743e3b3988327e53e5d974a71db455".into(),
        );

        Ok(rng().random_range(4..=15))
    }
}

// fn random_hex(len: usize) -> String {
//     const HEX_CHARS: &[u8] = b"0123456789abcdef";
//     let mut rng = ThreadRng::default();
//     let mut ret = String::with_capacity(len);
// 
//     for _ in 0..len {
//         let idx = rng.random_range(0..16);
//         ret.push(HEX_CHARS[idx] as char);
//     }
// 
//     ret
// }