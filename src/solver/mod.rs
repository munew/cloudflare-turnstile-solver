use crate::solver::task::TurnstileTask;
use crate::solver::user_fingerprint::Fingerprint;
use rand::{rng, Rng};
use std::fs;

pub(crate) mod challenge;
pub mod entries;
pub mod keys;
mod performance;
pub mod task;
mod task_client;
pub mod user_fingerprint;
mod utils;
pub mod vm_parser;
mod timezone;

#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub branch: String,
    pub version: String,
}

pub struct TurnstileSolver {
    fingerprints: Vec<Fingerprint>,
}

impl TurnstileSolver {
    pub async fn new() -> Self {
        let fp_str = fs::read("workspace/cloudflare_test.json").unwrap();

        let raw_values: Vec<serde_json::Value> = serde_json::from_slice(&fp_str).unwrap();

        let mut fps = Vec::new();
        for v in raw_values {
            if let Ok(fp) = serde_json::from_value::<Fingerprint>(v) {
                fps.push(fp);
            }
        }

        Self {
            fingerprints: fps,
        }
    }

    pub async fn create_task(
        &self,
        site_key: impl Into<String>,
        href: impl Into<String>,
        action: Option<String>,
        c_data: Option<String>,
    ) -> Result<TurnstileTask, anyhow::Error> {
        let fingerprint = self.get_fingerprint();
        let site_key = site_key.into();

        let task = TurnstileTask::new(
            site_key,
            href.into(),
            action,
            c_data,
            None,
            fingerprint,
        )?;

        Ok(task)
    }

    fn get_fingerprint(&self) -> &Fingerprint {
        &self.fingerprints[rng().random_range(0..self.fingerprints.len())]
    }
}