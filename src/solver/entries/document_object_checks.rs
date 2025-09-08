use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{json, Map, Value};

#[derive(Debug, Clone)]
pub struct DocumentObjectChecksEntry {
    pub window_name_key: String,
    pub document_stuff_length_key: String,
    pub document_events_key: String,
    pub document_title_key: String,
}

#[async_trait]
impl FingerprintEntryBase for DocumentObjectChecksEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let window_name_key = get_string_at_offset(quick_idx_map, strings, "", 1)?; // Yes, the base string is empty on purpose.
        let document_stuff_length_key = get_string_at_offset(quick_idx_map, strings, "onchange", -1)?;
        let document_events_key = get_string_at_offset(quick_idx_map, strings, "onload", 1)?;
        let document_title_key = get_string_at_offset(quick_idx_map, strings, "onload", 2)?;

        Ok(Self {
            window_name_key,
            document_stuff_length_key,
            document_events_key,
            document_title_key,
        })
    }


    async fn write_entry(
        &self,
        _: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        map.insert(self.window_name_key.clone(), "".into()); // cloudflare sets window.name to "" on purpose, no idea why.
        map.insert(
            self.document_stuff_length_key.clone(),
            json!([
                0, // document.links.length
                0, // document.images.length
                0, // document.forms.length
                0  // document.cookie.length
            ]),
        );
        map.insert(
            self.document_events_key.clone(),
            json!([
                "object", // typeof onchange
                "object", // typeof onclick
                "object", // typeof onmouseover
                "object", // typeof onmouseout
                "object", // typeof onkeydown
                "object"  // typeof onload
            ]),
        );
        map.insert(self.document_title_key.clone(), true.into()); // document.title !== undefined && document.title.length > 0
        Ok(rng().random_range(3..=10))
    }
}
