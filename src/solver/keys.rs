use serde::Serialize;

#[allow(dead_code)]
#[derive(Default, Debug, Serialize, Clone)]
pub struct InitPayloadKeys {
    pub c_type: String,                     // cType
    pub cv_id: String,                      // cvId
    pub payload_entries_count: String,      // 0
    pub prev_payload_entries_count: String, // 0
    pub perf_1: String,                     // perf.now() - perf.now()
    pub perf_2: String,                     // perf.now() - perf.now()
    pub unknown_3: String,                  // 1
    pub time: String,                       // cITimeS
    pub md: String,                         // md
    pub user_input: String,                 // contains touch, key, mouse, ...
    pub dont_care: String,
    pub dont_care_2: String,
    pub chl_dyn_key: String,
    pub encrypted_entry: String,
    pub empty_array: String,
    pub unknown_5: String,     // int
    pub chl_dyn_key_2: String, // string
    pub v_id: String,
    pub site_key: String,
    pub action: String,
    pub c_data: String,
    pub page_data: String,
    pub timeout_encountered: String,
    pub acch: String,
    pub u: String,
    pub url: String,
    pub origin: String,
    pub rc_v: String,
    pub reset_src: String,
    pub turnstile_age: String,
    pub widget_age: String,
    pub upgrade_attempts: String,
    pub upgrade_completed_count: String,
    pub time_to_init_ms: String,
    pub time_to_render_ms: String,
    pub time_to_params_ms: String,
    pub perf_3: String,
    pub perf_4: String,
    pub tief_time_ms: String,
    pub turnstile_u: String,
}

impl InitPayloadKeys {
    pub fn new(keys: Vec<String>) -> Self {
        let mut iter = keys.into_iter();
        Self {
            c_type: iter.next().unwrap_or_default(),
            cv_id: iter.next().unwrap_or_default(),
            payload_entries_count: iter.next().unwrap_or_default(),
            prev_payload_entries_count: iter.next().unwrap_or_default(),
            perf_1: iter.next().unwrap_or_default(),
            perf_2: iter.next().unwrap_or_default(),
            unknown_3: iter.next().unwrap_or_default(),
            time: iter.next().unwrap_or_default(),
            md: iter.next().unwrap_or_default(),
            user_input: iter.next().unwrap_or_default(),
            dont_care: iter.next().unwrap_or_default(),
            dont_care_2: iter.next().unwrap_or_default(),
            chl_dyn_key: iter.next().unwrap_or_default(),
            encrypted_entry: iter.next().unwrap_or_default(),
            empty_array: iter.next().unwrap_or_default(),
            unknown_5: iter.next().unwrap_or_default(),
            chl_dyn_key_2: iter.next().unwrap_or_default(),
            v_id: iter.next().unwrap_or_default(),
            site_key: iter.next().unwrap_or_default(),
            action: iter.next().unwrap_or_default(),
            c_data: iter.next().unwrap_or_default(),
            page_data: iter.next().unwrap_or_default(),
            timeout_encountered: iter.next().unwrap_or_default(),
            acch: iter.next().unwrap_or_default(),
            u: iter.next().unwrap_or_default(),
            url: iter.next().unwrap_or_default(),
            origin: iter.next().unwrap_or_default(),
            rc_v: iter.next().unwrap_or_default(),
            reset_src: iter.next().unwrap_or_default(),
            turnstile_age: iter.next().unwrap_or_default(),
            widget_age: iter.next().unwrap_or_default(),
            upgrade_attempts: iter.next().unwrap_or_default(),
            upgrade_completed_count: iter.next().unwrap_or_default(),
            time_to_init_ms: iter.next().unwrap_or_default(),
            time_to_render_ms: iter.next().unwrap_or_default(),
            time_to_params_ms: iter.next().unwrap_or_default(),
            perf_3: iter.next().unwrap_or_default(),
            perf_4: iter.next().unwrap_or_default(),
            tief_time_ms: iter.next().unwrap_or_default(),
            turnstile_u: iter.next().unwrap_or_default(),
        }
    }
}
