use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::Error;
use async_trait::async_trait;
use rand::{random_range, rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct DocumentEntry {
    xpath_key: String,
    pfp_key: String,
    scripts_length_key: String,
    style_sheets_length_key: String,
    meta_tags_length_key: String,
    tags_length_key: String,
    title_hash_key: String,
    href_key: String,
    null_shadow_root_key: String,
    window_self_is_top_key: String,
    ffp_key: String,
    wp_key: String,
}

#[async_trait]
impl FingerprintEntryBase for DocumentEntry {
    fn parse(quick_idx_map: &FxHashMap<String, usize>, strings: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let xpath_key = get_string_at_offset(quick_idx_map, strings, "xp", -1)?;
        let wp_key = get_string_at_offset(quick_idx_map, strings, "wp", -1)?;
        let pfp_key = get_string_at_offset(quick_idx_map, strings, "pfp", -1)?;
        let scripts_length_key = get_string_at_offset(quick_idx_map, strings, "sL", -1)?;
        let style_sheets_length_key = get_string_at_offset(quick_idx_map, strings, "ssL", -1)?;
        let meta_tags_length_key = get_string_at_offset(quick_idx_map, strings, "mL", -1)?;
        
        // We do not use "t" as base string as it could break with the weird "string obfuscation" that happens in the VM
        // It shouldn't be really a big deal as it doesn't seem like they randomize the order.
        let title_hash_key = get_string_at_offset(quick_idx_map, strings, "mL", 1)?;
        
        let tags_length_key = get_string_at_offset(quick_idx_map, strings, "tL", -1)?;
        let href_key = get_string_at_offset(quick_idx_map, strings, "lH", -1)?;
        let null_shadow_root_key = get_string_at_offset(quick_idx_map, strings, "sR", -1)?;
        let window_self_is_top_key = get_string_at_offset(quick_idx_map, strings, "ii", -1)?;
        let ffp_key = get_string_at_offset(quick_idx_map, strings, "ffp", -1)?;

        Ok(Self {
            xpath_key,
            wp_key,
            pfp_key,
            scripts_length_key,
            style_sheets_length_key,
            meta_tags_length_key,
            title_hash_key,
            tags_length_key,
            href_key,
            null_shadow_root_key,
            window_self_is_top_key,
            ffp_key,
        })
    }


    async fn write_entry(&self, task: &mut TurnstileTaskEntryContext, map: &mut Map<String, Value>) -> Result<usize, Error> {
        let wp = format!("{}|{}", random_range(15.0..20.0), random_range(1900.0..2000.0));
        
        map.insert(self.xpath_key.clone(), "/for[1]/div[1]/div[1]".into());
        map.insert(self.wp_key.clone(), wp.into());
        map.insert(self.pfp_key.clone(), "htm>hea>scr>-t-tscr_sr_de>-tbod>-tfor_ac_me>-tinp_ty_pl>-tinp_ty_pl>-tdiv_cl_da>div>".into());
        map.insert(self.scripts_length_key.clone(), 2.into());
        map.insert(self.style_sheets_length_key.clone(), 0.into());
        map.insert(self.meta_tags_length_key.clone(), 0.into());
        map.insert(self.title_hash_key.clone(), hash_title("").into());
        map.insert(self.tags_length_key.clone(), 12.into());
        map.insert(self.href_key.clone(), task.referrer.into());
        map.insert(self.null_shadow_root_key.clone(), true.into());
        map.insert(self.window_self_is_top_key.clone(), false.into());
        map.insert(self.ffp_key.clone(), "m:post|f:4|tphs".into());

        Ok(rng().random_range(4..=5))
    }
}

fn hash_title(e: &str) -> u32 {
    let mut t: u32 = 5381;

    for c in e.chars() {
        let o = c as u32;
        t = t.wrapping_mul(33) ^ o;
    }

    t
}