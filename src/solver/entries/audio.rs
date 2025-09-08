use crate::solver::entries::FingerprintEntryBase;
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::{Context, Error};
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct AudioEntry {
    pub hash_key: String,
    pub hash_alt_key: String,
}

#[async_trait]
impl FingerprintEntryBase for AudioEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let oncomplete_idx = quick_idx_map.get("oncomplete").context("audio entry: could not find oncomplete string index")?;
        let audio_hash_key_1 = strings.get(oncomplete_idx + 2).context("audio entry: could not find audio hash key 1")?;
        let audio_hash_key_2 = strings.get(oncomplete_idx + 3).context("audio entry: could not find audio hash key 2")?;

        Ok(Self {
            hash_key: audio_hash_key_1.to_string(),
            hash_alt_key: audio_hash_key_2.to_string(),
        })
    }

    async fn write_entry(&self, task: &mut TurnstileTaskEntryContext, map: &mut Map<String, Value>) -> Result<usize, Error> {
        map.insert(
            self.hash_key.clone(),
            task.fingerprint.audio.first_audio_hash.clone().into(),
        );

        map.insert(
            self.hash_alt_key.clone(),
            task.fingerprint.audio.second_audio_hash.clone().into(),
        );

        Ok(rng().random_range(11..30))
    }
}