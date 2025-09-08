use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

#[derive(Default, Clone, Debug)]
pub struct FloatWithoutZeros {
    pub value: f64,
}

impl FloatWithoutZeros {
    pub fn new(value: f64) -> Self {
        Self { value }
    }
}

impl Into<Value> for FloatWithoutZeros {
    fn into(self) -> Value {
        if self.value.fract() == 0.0 {
            return Value::Number(serde_json::Number::from(self.value as i64));
        }

        Value::Number(serde_json::Number::from_f64(self.value).unwrap())
    }
}

impl<'de> Deserialize<'de> for FloatWithoutZeros {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = f64::deserialize(deserializer)?;
        Ok(FloatWithoutZeros { value })
    }
}

impl Serialize for FloatWithoutZeros {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.value.fract() == 0.0 {
            serializer.serialize_i64(self.value as i64)
        } else {
            serializer.serialize_f64(self.value)
        }
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct BatteryInfo {
    pub charging: bool,
    pub level: FloatWithoutZeros,
    pub charging_time: isize,
    pub discharging_time: isize,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Headers {
    #[serde(rename(serialize = "Accept-Language", deserialize = "Accept-Language"))]
    pub accept_language: String,
    #[serde(rename(serialize = "User-Agent", deserialize = "User-Agent"))]
    pub user_agent: String,
    #[serde(rename(serialize = "Sec-Ch-Ua", deserialize = "Sec-Ch-Ua"))]
    pub sec_ch_ua: Option<String>,
    #[serde(rename(serialize = "Sec-Ch-Ua-Platform", deserialize = "Sec-Ch-Ua-Platform"))]
    pub sec_ch_ua_platform: Option<String>,
    #[serde(rename(serialize = "Sec-Ch-Ua-Mobile", deserialize = "Sec-Ch-Ua-Mobile"))]
    pub sec_ch_ua_mobile: Option<String>,
}

#[derive(Serialize, Default, Deserialize, Clone)]
pub struct UserPreferences {
    pub dark_mode: bool,
    pub forced_colors: bool,
    pub prefers_contrast: bool,
    pub prefers_reduced_motion: bool,
    pub battery_info: Option<BatteryInfo>,
}

#[derive(Serialize, Default, Deserialize, Clone)]
pub struct UserAgentDataBrand {
    pub brand: String,
    pub version: String,
}

#[derive(Serialize, Default, Deserialize, Clone)]
pub struct UserAgentDataFullVersion {
    pub brand: String,
    pub version: String,
}

#[derive(Serialize, Default, Deserialize, Clone)]
pub struct AudioHashes {
    pub first_audio_hash: String,
    pub second_audio_hash: String,
}

#[derive(Serialize, Default, Deserialize, Clone)]
pub struct UserAgentData {
    pub architecture: String,
    pub bitness: String,
    pub brands: Vec<UserAgentDataBrand>,
    #[serde(rename(serialize = "fullVersionList", deserialize = "fullVersionList"))]
    pub full_version_list: Vec<UserAgentDataFullVersion>,
    pub mobile: bool,
    pub model: String,
    pub platform: String,
    #[serde(rename(serialize = "platformVersion", deserialize = "platformVersion"))]
    pub platform_version: String,
}

#[derive(Serialize, Default, Deserialize, Clone)]
pub struct FingerprintWebGL {
    pub navigator_gpu_data: Option<Map<String, Value>>, 
    pub masked_vendor: String,
    pub masked_renderer: String,
    pub unmasked_vendor: String,
    pub unmasked_renderer: String,
    pub webgl_first_hash: String,
    pub webgl_second_hash: String,
}

#[derive(Serialize, Default, Deserialize, Clone)]
pub struct LanguageInfo {
    pub language: String,
    pub languages: Vec<String>,
    pub formatted_timezone: String,
    pub formatted_language: String,
    pub formatted_list: String,
    pub formatted_notation: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Fingerprint {
    pub platform: String,
    pub hardware_concurrency: u16,
    pub device_memory: u16,
    pub user_agent: String,
    pub user_agent_data: Option<UserAgentData>,
    pub user_preferences: UserPreferences,
    pub audio: AudioHashes,
    pub webgl: FingerprintWebGL,
    pub language_info: LanguageInfo,
    pub emoji_check_matches: bool,
    pub math_fingerprint: String,
    pub keys: Value,
    pub computed_style_hash: String,
    pub headers: Headers,
    pub html_bounds: Value,
}
