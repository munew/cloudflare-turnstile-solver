use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::{Context, Error};
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{json, Map, Value};

#[derive(Debug, Clone)]
pub struct WebGLEntry {
    pub masked_gpu_info_key: String,
    pub gpu_masked_vendor_key: String,
    pub gpu_masked_renderer_key: String,
    pub unmasked_gpu_info_key: String,
    pub gpu_unmasked_vendor_key: String,
    pub gpu_unmasked_renderer_key: String,
    pub no_navigator_gpu_data_key: String,
    pub prefix_key: String,
    pub suffix_key: String,
    pub encrypted_content_key: String,
}

#[async_trait]
impl FingerprintEntryBase for WebGLEntry {
    fn parse(
        quick_idx_map: &FxHashMap<String, usize>,
        strings: &[String],
        _: &[VMEntryValue],
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let masked_gpu_info_key = get_string_at_offset(quick_idx_map, strings, "getParameter", -2)?;
        let gpu_masked_vendor_key =
            get_string_at_offset(quick_idx_map, strings, "getParameter", -1)?;
        let gpu_masked_renderer_key =
            get_string_at_offset(quick_idx_map, strings, "getParameter", 2)?;
        let unmasked_gpu_info_key =
            get_string_at_offset(quick_idx_map, strings, "WEBGL_debug_renderer_info", 1)?;
        let gpu_unmasked_vendor_key =
            get_string_at_offset(quick_idx_map, strings, "WEBGL_debug_renderer_info", 2)?;
        let gpu_unmasked_renderer_key =
            get_string_at_offset(quick_idx_map, strings, "UNMASKED_VENDOR_WEBGL", 1)?;

        let prefix_key = get_string_at_offset(quick_idx_map, strings, "substring", -1)?;
        let suffix_key = get_string_at_offset(quick_idx_map, strings, "substring", 1)?;
        
        let no_navigator_gpu_data_key = get_string_at_offset(quick_idx_map, strings, "info", -1)?;

        // find first possible key
        let encrypted_content_key = strings
            .iter()
            .find(|k| k.len() == 5 || k.len() == 6)
            .context("Could not find encrypted content key")?
            .to_string();

        Ok(Self {
            masked_gpu_info_key,
            gpu_masked_vendor_key,
            gpu_masked_renderer_key,
            unmasked_gpu_info_key,
            gpu_unmasked_vendor_key,
            gpu_unmasked_renderer_key,
            prefix_key,
            suffix_key,
            encrypted_content_key,
            no_navigator_gpu_data_key,
        })
    }

    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        // dbg!(self);
        let fingerprint = &task.fingerprint;

        let mut gpu_info_object: Map<String, Value> = serde_json::Map::new();

        let mut masked_info_object: Map<String, Value> = serde_json::Map::new();
        masked_info_object.insert(
            self.gpu_masked_vendor_key.clone(),
            fingerprint.webgl.masked_vendor.clone().into(),
        );
        masked_info_object.insert(
            self.gpu_masked_renderer_key.clone(),
            fingerprint.webgl.masked_renderer.clone().into(),
        );
        gpu_info_object.insert(self.masked_gpu_info_key.clone(), masked_info_object.into());

        let mut unmasked_info_object: Map<String, Value> = serde_json::Map::new();
        unmasked_info_object.insert(
            self.gpu_unmasked_vendor_key.clone(),
            task.fingerprint.webgl.unmasked_vendor.clone().into(),
        );
        unmasked_info_object.insert(
            self.gpu_unmasked_renderer_key.clone(),
            task.fingerprint.webgl.unmasked_renderer.clone().into(),
        );
        gpu_info_object.insert(
            self.unmasked_gpu_info_key.clone(),
            unmasked_info_object.into(),
        );
        
        let mapped_gpu_data = task.fingerprint.webgl.navigator_gpu_data
            .as_ref()
            .map(|v| Value::Object(v.clone()))
            .unwrap_or_else(|| Value::String(self.no_navigator_gpu_data_key.clone().into()));

        let encrypted = task.encryption.encrypt(json!([
            format!("{}{}{}", self.prefix_key, task.fingerprint.webgl.webgl_first_hash, self.suffix_key),
            format!("{}{}{}", self.prefix_key, task.fingerprint.webgl.webgl_second_hash, self.suffix_key),
            gpu_info_object,
            mapped_gpu_data,
        ]));

        map.insert(self.encrypted_content_key.clone(), encrypted.into());

        Ok(rng().random_range(160..=280))
    }
}
