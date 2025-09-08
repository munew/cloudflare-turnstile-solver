use crate::reverse::encryption::decrypt_cloudflare_response;
use crate::solver::challenge::CloudflareChallengeOptions;
use crate::solver::performance::{PerformanceEntry, PerformanceResourceEntry};
use crate::solver::timezone::get_timezone;
use crate::solver::user_fingerprint::Headers;
use crate::solver::utils::imprecise_performance_now_value;
use crate::solver::VersionInfo;
use anyhow::{bail};
use rand::Rng;
use rquest::header::{HeaderMap, HeaderName, HeaderValue};
use rquest::{Client, EmulationProviderFactory, Version};
use rquest_util::Emulation::Chrome136;
use rquest_util::EmulationOS::Windows;
use rquest_util::{EmulationOption};
use std::io::Read;
use std::time::{Duration, Instant};
use url::Url;

pub struct TaskClient {
    client: Client,
    host: String,

    branch: String,
    solve_url: Option<String>,
}

impl TaskClient {
    pub(crate) fn new(
        referrer: String,
        headers: Headers,
    ) -> Result<TaskClient, anyhow::Error> {
        let emulation = EmulationOption::builder()
            .emulation(Chrome136)
            .emulation_os(Windows)
            .build();

        let client = build_client(emulation, None, headers)?;
        Ok(Self {
            host: get_referrer_host(referrer.as_str())?,
            client,
            branch: "b".to_string(),
            solve_url: None,
        })
    }

    pub(crate) async fn get_api(&mut self) -> Result<VersionInfo, anyhow::Error> {
        self.branch = "b".to_string();
        Ok(VersionInfo {
            branch: "b".to_string(),
            version: "8359bcf47b68".to_string(),
        })
    }

    pub(crate) async fn get_random_image(
        &mut self,
        zone: &str,
    ) -> Result<PerformanceEntry, anyhow::Error> {
        self.set_get_headers_order();
        let url = format!(
            "https://{}/cdn-cgi/challenge-platform/h/{}/cmg/1",
            zone, &self.branch
        );

        let response = self
            .client
            .get(&url)
            .header(
                "Accept",
                "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
            )
            .header("Sec-Fetch-Site", "same-origin")
            .header("Sec-Fetch-Mode", "no-cors")
            .header("Sec-Fetch-Dest", "image")
            .header("Referer", self.solve_url.as_ref().unwrap())
            .header("Priority", "i")
            .send()
            .await?;

        if response.status() != 200 {
            bail!(
                "received invalid status code when getting random image: {}",
                response.status()
            );
        }

        Ok(PerformanceEntry::Resource(PerformanceResourceEntry {
            r#type: "r".to_string(),
            time_taken: imprecise_performance_now_value(510.0),
            initiator_type: "link".to_string(),
            name: url,
            next_hop_protocol: "h2".to_string(),
            transfer_size: 386,
            encoded_body_size: 61,
        }))
    }

    pub(crate) async fn get_timezone(&mut self) -> Result<String, anyhow::Error> {
        let response = self
            .client
            .get("http://icanhazip.com")
            .header("accept-encoding", "identity")
            .version(Version::HTTP_11)
            .send()
            .await?;

        if response.status() != 200 {
            bail!(
                "received invalid status code when getting ip: {}",
                response.status()
            );
        }

        let text = response.text().await?.replace("\n", "");
        get_timezone(&text)
    }

    pub(crate) async fn initialize_solve(
        &mut self,
        site_key: &str,
    ) -> Result<(String, String, CloudflareChallengeOptions), anyhow::Error> {
        self.set_get_html_headers_order();
        let solve_url = generate_solve_url(self.branch.as_str(), site_key);

        let response = self
            .client
            .get(solve_url.as_str())
            .header("Upgrade-Insecure-Requests", "1")
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
            .header("Sec-Fetch-Site", "cross-site")
            .header("Sec-Fetch-Mode", "navigate")
            .header("Sec-Fetch-Dest", "iframe")
            .header("Referer", &self.host)
            .header("Priority", "u=0, i")
            .send()
            .await?;

        let content_encoding = response
            .headers()
            .get("Content-Encoding")
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_str("").unwrap())
            .to_str()?
            .to_string();
        let bytes = response.bytes().await?;
        let decompressed = decompress_body(bytes.as_ref(), &content_encoding).unwrap();
        let text = String::from_utf8(decompressed)?;

        let challenge = CloudflareChallengeOptions::from_html(text.as_str())?;
        self.solve_url = Some(solve_url.clone());

        Ok((solve_url, text, challenge))
    }

    pub(crate) async fn get_orchestrate(
        &mut self,
        zone: &str,
        c_ray: &str,
    ) -> Result<(PerformanceEntry, String), anyhow::Error> {
        self.set_get_headers_order();
        let t = Instant::now();

        let url = format!(
            "https://{}/cdn-cgi/challenge-platform/h/{}/orchestrate/chl_api/v1?ray={}&lang=auto",
            zone, self.branch, c_ray
        );

        let response = self
            .client
            .get(&url)
            .header("Accept", "*/*")
            .header("Sec-Fetch-Site", "same-origin")
            .header("Sec-Fetch-Mode", "no-cors")
            .header("Sec-Fetch-Dest", "script")
            .header("Referer", self.solve_url.as_ref().unwrap())
            .header("Priority", "u=1")
            .redirect(rquest::redirect::Policy::none())
            .send()
            .await?;

        let content_encoding = response
            .headers()
            .get("Content-Encoding")
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_str("").unwrap())
            .to_str()?
            .to_string();
        let bytes = response.bytes().await?;
        let decompressed = decompress_body(bytes.as_ref(), &content_encoding).unwrap();
        let text = String::from_utf8(decompressed)?;
        Ok((
            PerformanceEntry::Resource(PerformanceResourceEntry {
                r#type: "r".to_string(),
                time_taken: imprecise_performance_now_value(
                    ((t.elapsed().as_micros() / 100) as f64) / 10.0,
                ),
                initiator_type: "script".to_string(),
                name: url,
                next_hop_protocol: "h2".to_string(),
                transfer_size: bytes.len() + 300, // don't worry
                encoded_body_size: bytes.len(),
            }),
            text,
        ))
    }

    pub async fn get_image(
        &mut self,
        path: &str,
    ) -> Result<(PerformanceEntry, Vec<u8>), anyhow::Error> {
        self.set_get_headers_order();

        let url = format!(
            "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/{}{}",
            self.branch, path
        );

        let t = Instant::now();

        let response = self
            .client
            .get(&url)
            .header(
                "Accept",
                "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
            )
            .header("Sec-Fetch-Site", "same-origin")
            .header("Sec-Fetch-Mode", "no-cors")
            .header("Sec-Fetch-Dest", "image")
            .header("Referer", self.solve_url.as_ref().unwrap())
            .header("Priority", "i")
            .send()
            .await?;

        if response.status() != 200 {
            return Err(anyhow::anyhow!(
                "Received invalid status code when parsing challenge image: {} {}",
                response.status(),
                response.text().await?
            ));
        }

        let content_encoding = response
            .headers()
            .get("Content-Encoding")
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_str("").unwrap())
            .to_str()?
            .to_string();
        let bytes = response.bytes().await?;
        let decompressed = decompress_body(bytes.as_ref(), &content_encoding).unwrap();

        Ok((
            PerformanceEntry::Resource(PerformanceResourceEntry {
                r#type: "r".to_string(),
                time_taken: imprecise_performance_now_value(
                    ((t.elapsed().as_micros() / 100) as f64) / 10.0,
                ),
                initiator_type: "img".to_string(),
                name: url,
                next_hop_protocol: "h2".to_string(),
                transfer_size: bytes.len() + 300, // don't worry
                encoded_body_size: bytes.len(),
            }),
            decompressed,
        ))
    }

    pub async fn get_pat(&mut self, path: &str) -> Result<PerformanceEntry, anyhow::Error> {
        self.set_get_headers_order();

        let t = Instant::now();
        let url = format!(
            "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/{}{}",
            self.branch, path
        );

        let response = self
            .client
            .get(&url)
            .header("Cache-Control", "max-age=0")
            .header("Accept", "*/*")
            .header("Sec-Fetch-Site", "same-origin")
            .header("Sec-Fetch-Mode", "cors")
            .header("Sec-Fetch-Dest", "empty")
            .header("Referer", self.solve_url.as_ref().unwrap())
            .header("Priority", "u=1, i")
            .send()
            .await?;

        if response.status() != 401 {
            return Err(anyhow::anyhow!(
                "Received unexpected status code when parsing PAT: {} {}",
                response.status(),
                response.text().await?
            ));
        }

        let bytes = response.bytes().await?;

        Ok(PerformanceEntry::Resource(PerformanceResourceEntry {
            r#type: "r".to_string(),
            time_taken: imprecise_performance_now_value(
                ((t.elapsed().as_micros() / 100) as f64) / 10.0,
            ),
            initiator_type: "fetch".to_string(),
            name: url,
            next_hop_protocol: "h2".to_string(),
            transfer_size: bytes.len() + 300, // don't worry
            encoded_body_size: bytes.len(),
        }))
    }

    pub(crate) async fn post_init_payload(
        &mut self,
        compressed_payload: String,
        zone: &str,
        init_arg: &str,
        c_ray: &str,
        ch: &str,
    ) -> Result<(PerformanceEntry, String), anyhow::Error> {
        self.set_post_headers_order();

        let url = format!(
            "https://{}/cdn-cgi/challenge-platform/h/{}/flow/ov1{}{}/{}",
            zone, self.branch, init_arg, c_ray, ch,
        );

        let t = Instant::now();
        let response = self
            .client
            .post(&url)
            .header("Content-Length", compressed_payload.len().to_string())
            .header("Content-Type", "text/plain;charset=UTF-8")
            .header("cf-chl", ch)
            .header("cf-chl-ra", "0")
            .header("Accept", "*/*")
            .header("Origin", format!("https://{zone}"))
            .header("Sec-Fetch-Site", "same-origin")
            .header("Sec-Fetch-Mode", "cors")
            .header("Sec-Fetch-Dest", "empty")
            .header("Referer", self.solve_url.as_ref().unwrap())
            .header("Priority", "u=2")
            .body(compressed_payload.clone())
            .send()
            .await?;

        if response.status() != 200 {
            return Err(anyhow::anyhow!(
                "Received invalid status code when sending init payload: {} {}",
                response.status(),
                response.text().await?
            ));
        }

        let content_encoding = response
            .headers()
            .get("Content-Encoding")
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_str("").unwrap())
            .to_str()?
            .to_string();
        let bytes = response.bytes().await?;
        let decompressed = decompress_body(bytes.as_ref(), &content_encoding).unwrap();
        let text = String::from_utf8(decompressed)?;

        Ok((
            PerformanceEntry::Resource(PerformanceResourceEntry {
                r#type: "r".to_string(),
                time_taken: imprecise_performance_now_value(
                    ((t.elapsed().as_micros() / 100) as f64) / 10.0,
                ),
                initiator_type: "xmlhttprequest".to_string(),
                name: url,
                next_hop_protocol: "h2".to_string(),
                transfer_size: bytes.len() + 300, // don't worry
                encoded_body_size: bytes.len(),
            }),
            text,
        ))
    }

    pub(crate) async fn post_payload(
        &mut self,
        url: &str,
        compressed_payload: String,
        chl: &str,
        c_ray: &str,
    ) -> Result<String, anyhow::Error> {
        let parsed = Url::parse(url)?;
        self.set_post_headers_order();

        let response = self
            .client
            .post(url)
            .header("Content-Length", compressed_payload.len().to_string())
            .header("Content-Type", "text/plain;charset=UTF-8")
            .header("cf-chl", chl)
            .header("cf-chl-ra", "0")
            .header("Accept", "*/*")
            .header("Origin", format!("https://{}", parsed.host().unwrap()))
            .header("Sec-Fetch-Site", "same-origin")
            .header("Sec-Fetch-Mode", "cors")
            .header("Sec-Fetch-Dest", "empty")
            .header("Referer", self.solve_url.as_ref().unwrap())
            .header("Priority", "u=1, i")
            .body(compressed_payload)
            .send()
            .await?;

        if response.status() != 200 {
            bail!(
                "Received invalid status code when sending second payload: {} {}",
                response.status(),
                response.text().await?
            );
        }

        let content_encoding = response
            .headers()
            .get("Content-Encoding")
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_str("").unwrap())
            .to_str()?
            .to_string();
        let bytes = response.bytes().await?;
        let decompressed = decompress_body(bytes.as_ref(), &content_encoding).unwrap();
        let text = String::from_utf8(decompressed)?;

        decrypt_cloudflare_response(c_ray, &text)
    }

    pub(crate) fn get_branch(&self) -> &str {
        &self.branch
    }

    fn set_get_headers_order(&mut self) {
        let order = vec![
            HeaderName::from_static("cache-control"),
            HeaderName::from_static("sec-ch-ua-platform"),
            HeaderName::from_static("user-agent"),
            HeaderName::from_static("sec-ch-ua"),
            HeaderName::from_static("cf-chl"),
            HeaderName::from_static("cf-chl-ra"),
            HeaderName::from_static("sec-ch-ua-mobile"),
            HeaderName::from_static("accept"),
            HeaderName::from_static("sec-fetch-site"),
            HeaderName::from_static("sec-fetch-mode"),
            HeaderName::from_static("sec-fetch-dest"),
            HeaderName::from_static("sec-fetch-storage-access"),
            HeaderName::from_static("referer"),
            HeaderName::from_static("accept-encoding"),
            HeaderName::from_static("accept-language"),
            HeaderName::from_static("cookie"),
            HeaderName::from_static("priority"),
        ];

        self.client.update().headers_order(order).apply().unwrap();
    }

    fn set_get_html_headers_order(&mut self) {
        let order = vec![
            HeaderName::from_static("sec-ch-ua"),
            HeaderName::from_static("sec-ch-ua-mobile"),
            HeaderName::from_static("sec-ch-ua-platform"),
            HeaderName::from_static("upgrade-insecure-requests"),
            HeaderName::from_static("user-agent"),
            HeaderName::from_static("accept"),
            HeaderName::from_static("sec-fetch-site"),
            HeaderName::from_static("sec-fetch-mode"),
            HeaderName::from_static("sec-fetch-dest"),
            HeaderName::from_static("sec-fetch-storage-access"),
            HeaderName::from_static("referer"),
            HeaderName::from_static("accept-encoding"),
            HeaderName::from_static("accept-language"),
            HeaderName::from_static("cookie"),
            HeaderName::from_static("priority"),
        ];

        self.client.update().headers_order(order).apply().unwrap();
    }

    fn set_post_headers_order(&mut self) {
        let order = vec![
            HeaderName::from_static("content-length"),
            HeaderName::from_static("sec-ch-ua-platform"),
            HeaderName::from_static("user-agent"),
            HeaderName::from_static("sec-ch-ua"),
            HeaderName::from_static("content-type"),
            HeaderName::from_static("cf-chl"),
            HeaderName::from_static("cf-chl-ra"),
            HeaderName::from_static("sec-ch-ua-mobile"),
            HeaderName::from_static("accept"),
            HeaderName::from_static("origin"),
            HeaderName::from_static("sec-fetch-site"),
            HeaderName::from_static("sec-fetch-mode"),
            HeaderName::from_static("sec-fetch-dest"),
            HeaderName::from_static("sec-fetch-storage-access"),
            HeaderName::from_static("referer"),
            HeaderName::from_static("accept-encoding"),
            HeaderName::from_static("accept-language"),
            HeaderName::from_static("cookie"),
            HeaderName::from_static("priority"),
        ];

        self.client.update().headers_order(order).apply().unwrap();
    }
}

fn get_referrer_host(referrer: &str) -> Result<String, anyhow::Error> {
    let parsed = Url::parse(referrer)?;
    Ok(parsed.origin().ascii_serialization() + "/")
}

const ENABLE_FEEDBACK: bool = true;
const THEME: &str = "auto";
const LANGUAGE: &str = "auto";

fn generate_solve_url(branch: &str, site_key: &str) -> String {
    let feedback_param = if ENABLE_FEEDBACK { "fbE" } else { "fbD" };

    format!(
        "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/{}/turnstile/if/ov2/av0/rcv/{}/{}/{}/{}/new/normal/{}/",
        branch,
        generate_widget_id(),
        site_key,
        THEME,
        feedback_param,
        LANGUAGE,
    )
}

fn generate_widget_id() -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    let mut rng = rand::rng();
    let mut r = String::new();

    for _ in 0..5 {
        let idx = rng.random_range(0..chars.len());
        r.push(chars[idx]);
    }

    r
}

fn build_client<P>(
    emulation: P,
    proxy: Option<String>,
    headers: Headers,
) -> Result<Client, anyhow::Error>
where
    P: EmulationProviderFactory,
{
    let mut header_map = HeaderMap::new();

    header_map.insert("Accept-Language", headers.accept_language.parse()?);
    header_map.insert("User-Agent", headers.user_agent.parse()?);
    header_map.insert("Accept-Encoding", "gzip, deflate, br, zstd".parse()?);

    if let (Some(sec_ch_ua), Some(sec_ch_ua_mobile), Some(sec_ch_ua_platform)) = (
        headers.sec_ch_ua,
        headers.sec_ch_ua_mobile,
        headers.sec_ch_ua_platform,
    ) {
        header_map.insert("Sec-Fetch-Storage-Access", "active".parse()?);
        header_map.insert("sec-ch-ua", sec_ch_ua.parse()?);
        header_map.insert("sec-ch-ua-mobile", sec_ch_ua_mobile.parse()?);
        header_map.insert("sec-ch-ua-platform", sec_ch_ua_platform.parse()?);
    }

    let mut builder = Client::builder()
        .emulation(emulation)
        .cert_verification(!cfg!(debug_assertions))
        .gzip(false)
        .brotli(false)
        .deflate(false)
        .zstd(false)
        .timeout(Duration::from_secs(15))
        .pool_idle_timeout(Some(Duration::from_millis(30000)))
        .default_headers(header_map);

    if let Some(p) = proxy {
        builder = builder.proxy(p);
    }

    builder.build().map_err(|e| anyhow::anyhow!(e))
}

pub fn decompress_body(
    bytes: &[u8],
    encoding: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match encoding.to_lowercase().as_str() {
        "gzip" => {
            let mut decoder = flate2::read::GzDecoder::new(bytes);
            let mut decoded = Vec::new();
            decoder.read_to_end(&mut decoded)?;
            Ok(decoded)
        }
        "deflate" => {
            let mut decoder = flate2::read::ZlibDecoder::new(bytes);
            let mut decoded = Vec::new();
            decoder.read_to_end(&mut decoded)?;
            Ok(decoded)
        }
        "br" => {
            let mut decoder = brotli::Decompressor::new(bytes, 4096);
            let mut decoded = Vec::new();
            decoder.read_to_end(&mut decoded)?;
            Ok(decoded)
        }
        "zstd" => {
            let mut decoder = zstd::stream::Decoder::new(bytes)?;
            let mut decoded = Vec::new();
            decoder.read_to_end(&mut decoded)?;
            Ok(decoded)
        }
        "" | "identity" => {
            // No compression
            Ok(bytes.to_vec())
        }
        other => Err(format!("Unsupported encoding: {}", other).into()),
    }
}
