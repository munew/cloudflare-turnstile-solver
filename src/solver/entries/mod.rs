pub mod audio;
pub mod browser_data;
pub mod browser_keys;
pub mod computed_style;
pub mod css;
pub mod div_render_time;
pub mod document;
pub mod document_object_checks;
pub mod element_parent_checks;
pub mod emoji_os_check;
pub mod engine_behavior;
pub mod eval_error;
pub mod html_render;
pub mod image;
pub mod language;
pub mod math;
pub mod pat;
pub mod performance;
pub mod performance_memory;
pub mod pow;
pub mod pow_click;
pub mod selenium;
pub mod stack;
pub mod static_value;
pub mod tampering_plugins;
pub mod timezone;
pub mod unknown_hashes;
pub mod user_agent_data;
pub mod user_prefs_battery;
pub mod web_gl;
pub mod web_gl_native_fn_checks;
pub mod worker_performance_timing;

use crate::solver::entries::audio::AudioEntry;
use crate::solver::entries::browser_data::BrowserDataEntry;
use crate::solver::entries::browser_keys::BrowserKeysEntry;
use crate::solver::entries::computed_style::ComputedStyleEntry;
use crate::solver::entries::document::DocumentEntry;
use crate::solver::entries::document_object_checks::DocumentObjectChecksEntry;
use crate::solver::entries::element_parent_checks::ElementParentChecksEntry;
use crate::solver::entries::emoji_os_check::EmojiOsCheckEntry;
use crate::solver::entries::engine_behavior::EngineBehaviorEntry;
use crate::solver::entries::eval_error::EvalErrorEntry;
use crate::solver::entries::html_render::HTMLRenderEntry;
use crate::solver::entries::image::ImageEntry;
use crate::solver::entries::language::LanguageEntry;
use crate::solver::entries::math::MathEntry;
use crate::solver::entries::pat::PrivateAccessTokenEntry;
use crate::solver::entries::performance::PerformanceEntriesEntry;
use crate::solver::entries::performance_memory::PerformanceMemoryEntry;
use crate::solver::entries::pow::POWEntry;
use crate::solver::entries::stack::StackEntry;
use crate::solver::entries::static_value::StaticValueEntry;
use crate::solver::entries::tampering_plugins::TamperingAndPluginsEntry;
use crate::solver::entries::timezone::TimezoneEntry;
use crate::solver::entries::unknown_hashes::UnknownHashesEntry;
use crate::solver::entries::user_agent_data::UserAgentDataEntry;
use crate::solver::entries::user_prefs_battery::UserPreferencesAndBatteryEntry;
use crate::solver::entries::web_gl::WebGLEntry;
use crate::solver::entries::web_gl_native_fn_checks::WebGLNativeFunctionChecksEntry;
use crate::solver::entries::worker_performance_timing::WorkerPerformanceTimingEntry;
use crate::solver::vm_parser::{TurnstileTaskEntryContext, VMEntryValue};
use anyhow::{Context, Error};
use async_trait::async_trait;
use css::CssEntry;
use div_render_time::DivRenderTimeEntry;
use pow_click::POWClickEntry;
use rustc_hash::FxHashMap;
use selenium::SeleniumEntry;
use strum::ToString;

#[derive(Debug, Clone, ToString)]
pub enum FingerprintEntry {
    BrowserData(BrowserDataEntry),
    BrowserKeys(BrowserKeysEntry),
    EmojiOsCheck(EmojiOsCheckEntry),
    DocumentObjectChecks(DocumentObjectChecksEntry),
    POW(POWEntry),
    POWClick(POWClickEntry),
    Audio(AudioEntry),
    UserPreferencesAndBattery(UserPreferencesAndBatteryEntry),
    Timezone(TimezoneEntry),
    PrivateAccessToken(PrivateAccessTokenEntry),
    SeleniumUnknown(SeleniumEntry),
    Stack(StackEntry), // this could be invalid
    DivRenderTime(DivRenderTimeEntry),
    StaticValue(StaticValueEntry), // is there three times
    UserAgentData(UserAgentDataEntry),
    Performance(PerformanceEntriesEntry),
    UnknownHashes(UnknownHashesEntry),
    Image(ImageEntry), // sends encrypted width+height of image
    CSS(CssEntry),
    WebGL(WebGLEntry),
    WebGLNativeFunctionChecks(WebGLNativeFunctionChecksEntry),
    Document(DocumentEntry), // values generated in api.js
    ElementParentChecks(ElementParentChecksEntry),
    Language(LanguageEntry),
    // StaticValue again,
    // StaticValue again,
    WorkerPerformanceTiming(WorkerPerformanceTimingEntry),
    Math(MathEntry),
    HTMLRender(HTMLRenderEntry),
    PerformanceMemory(PerformanceMemoryEntry),
    EngineBehavior(EngineBehaviorEntry),
    EvalError(EvalErrorEntry),
    ComputedStyle(ComputedStyleEntry), // sha-256 computed style and get first 32 chars
    TamperingAndPlugins(TamperingAndPluginsEntry),
}

#[derive(Debug, Clone)]
pub struct NullEntry;

#[async_trait]
impl FingerprintEntryBase for NullEntry {
    fn parse(_: &FxHashMap<String, usize>, _: &[String], _: &[VMEntryValue]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(Self {})
    }

    async fn write_entry(
        &self,
        _: &mut TurnstileTaskEntryContext,
        _: &mut serde_json::Map<String, serde_json::Value>,
    ) -> Result<usize, Error> {
        Ok(0)
    }
}

impl FingerprintEntry {
    pub fn as_entry_base(&self) -> &dyn FingerprintEntryBase {
        match self {
            FingerprintEntry::BrowserData(entry) => entry,
            FingerprintEntry::BrowserKeys(entry) => entry,
            FingerprintEntry::EmojiOsCheck(entry) => entry,
            FingerprintEntry::DocumentObjectChecks(entry) => entry,
            FingerprintEntry::POW(entry) => entry,
            FingerprintEntry::POWClick(entry) => entry,
            FingerprintEntry::Audio(entry) => entry,
            FingerprintEntry::UserPreferencesAndBattery(entry) => entry,
            FingerprintEntry::Timezone(entry) => entry,
            FingerprintEntry::PrivateAccessToken(entry) => entry,
            FingerprintEntry::SeleniumUnknown(entry) => entry,
            FingerprintEntry::Stack(entry) => entry,
            FingerprintEntry::DivRenderTime(entry) => entry,
            FingerprintEntry::StaticValue(entry) => entry,
            FingerprintEntry::UserAgentData(entry) => entry,
            FingerprintEntry::Performance(entry) => entry,
            FingerprintEntry::UnknownHashes(entry) => entry,
            FingerprintEntry::Image(entry) => entry,
            FingerprintEntry::EvalError(entry) => entry,
            FingerprintEntry::CSS(entry) => entry,
            FingerprintEntry::WebGL(entry) => entry,
            FingerprintEntry::WebGLNativeFunctionChecks(entry) => entry,
            FingerprintEntry::Document(entry) => entry,
            FingerprintEntry::ElementParentChecks(entry) => entry,
            FingerprintEntry::Language(entry) => entry,
            FingerprintEntry::WorkerPerformanceTiming(entry) => entry,
            FingerprintEntry::Math(entry) => entry,
            FingerprintEntry::HTMLRender(entry) => entry,
            FingerprintEntry::PerformanceMemory(entry) => entry,
            FingerprintEntry::EngineBehavior(entry) => entry,
            FingerprintEntry::ComputedStyle(entry) => entry,
            FingerprintEntry::TamperingAndPlugins(entry) => entry,
        }
    }
}

#[async_trait]
pub trait FingerprintEntryBase {
    fn parse(
        quick_idx_map: &FxHashMap<String, usize>,
        strings: &[String],
        values: &[VMEntryValue],
    ) -> Result<Self, Error>
    where
        Self: Sized;
    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut serde_json::Map<String, serde_json::Value>,
    ) -> Result<usize, Error>;
}

pub(in crate::solver::entries) fn get_string_at_offset(
    quick_idx_map: &FxHashMap<String, usize>,
    strings: &[String],
    base_string: &str,
    offset: isize,
) -> Result<String, Error> {
    let idx = *quick_idx_map
        .get(base_string)
        .with_context(|| format!("could not find base string {base_string}"))?;
    let string = strings
        .get(((idx as isize) + offset) as usize)
        .with_context(|| format!("could not find string from {base_string}+{idx}"))?;

    Ok(string.clone())
}
