use anyhow::anyhow;
use regex::Regex;

#[derive(Debug)]
pub struct CloudflareChallengeOptions {
    pub c_type: String,
    pub cv_id: String,
    pub c_arg: String,
    pub zone: String,
    pub api_v_id: String,
    pub widget_id: String,
    pub site_key: String,
    pub api_mode: String,
    pub api_size: String,
    pub api_rcv: String,
    pub reset_src: String,
    pub c_ray: String,
    pub ch: String,
    pub md: String,
    pub time: String,
    pub iss_ua: String,
    pub ip: String,
    pub turnstile_u: String,
}

impl CloudflareChallengeOptions {
    pub fn from_html(html: &str) -> Result<Self, anyhow::Error> {
        let start_marker = "window._cf_chl_opt={";
        let end_marker = "};";

        let start = html
            .find(start_marker)
            .ok_or_else(|| anyhow!("Failed to find challenge data start"))?
            + start_marker.len();
        let end = html[start..]
            .find(end_marker)
            .ok_or_else(|| anyhow!("Failed to find challenge data end"))?;
        let data = &html[start..start + end];

        fn extract_field(data: &str, key: &str) -> String {
            let pat = format!(r#"{}\s*:\s*['"]([^'"]*)['"]"#, key);
            Regex::new(&pat)
                .ok()
                .and_then(|re| re.captures(data))
                .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
                .unwrap_or_default()
        }

        fn get_turnstile_u(html: &str) -> String {
            html.split("chlTimeoutMs:")
                .nth(1)
                .and_then(|s| s.split(',').nth(1))
                .and_then(|raw| raw.split(['\'', '"']).nth(1))
                .map(str::to_string)
                .unwrap_or_default()
        }
        

        Ok(CloudflareChallengeOptions {
            c_type: extract_field(data, "cType"),
            cv_id: extract_field(data, "cvId"),
            c_arg: extract_field(data, "cFPWv"),
            zone: extract_field(data, "cZone"),
            api_v_id: extract_field(data, "chlApivId"),
            widget_id: extract_field(data, "chlApiWidgetId"),
            site_key: extract_field(data, "chlApiSitekey"),
            api_mode: extract_field(data, "chlApiMode"),
            api_size: extract_field(data, "chlApiSize"),
            api_rcv: extract_field(data, "chlApiRcV"),
            c_ray: extract_field(data, "cRay"),
            ch: extract_field(data, "cH"),
            md: extract_field(data, "md"),
            time: extract_field(data, "cITimeS"),
            iss_ua: extract_field(data, "chlIssUA"),
            ip: extract_field(data, "chlIp"),
            reset_src: extract_field(data, "chlApiResetSrc"),
            turnstile_u: get_turnstile_u(html),
        })
    }
}
