use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::user_fingerprint::FloatWithoutZeros;
use crate::solver::utils::imprecise_performance_now_value;
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::{bail, Context, Error};
use async_trait::async_trait;
use rand::prelude::ThreadRng;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::time::SystemTime;

#[derive(Clone, Debug)]
pub struct POWEntry {
    pow_string_key: String,
    pow_string_value: String,
    difficulty_key: String,
    difficulty: isize,
    hash_key: String,
    hash_value: String,
    result_key: String,
    found_hash_key: String,
    iterations_count_key: String,
    time_spent_key: String,
}

#[async_trait]
impl FingerprintEntryBase for POWEntry {
    fn parse(
        quick_idx_map: &FxHashMap<String, usize>,
        strings: &[String],
        values: &[VMEntryValue],
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let pow_string_key = get_string_at_offset(quick_idx_map, strings, "performance##1", -5)?;
        let pow_string_value = get_string_at_offset(quick_idx_map, strings, "performance##1", -4)?;
        let difficulty_key = get_string_at_offset(quick_idx_map, strings, "performance##1", -3)?;

        let difficulty_key_value_idx = values
            .iter()
            .position(|k| {
                if let VMEntryValue::String(s) = k
                    && *s == difficulty_key
                {
                    return true;
                }

                false
            })
            .context("could not find difficulty key value idx")?;

        let difficulty = match values
            .get(difficulty_key_value_idx + 1)
            .context("expected a value after difficulty key")?
        {
            VMEntryValue::Integer(i) => *i,
            _ => bail!(format!(
                "expected difficulty int value: {:?}",
                values.get(difficulty_key_value_idx + 1)
            )),
        };

        let hash_key = get_string_at_offset(quick_idx_map, strings, "performance##1", -2)?;
        let hash_value = get_string_at_offset(quick_idx_map, strings, "performance##1", -1)?;
        let result_key = get_string_at_offset(
            quick_idx_map,
            strings,
            "the force is not strong with this one",
            -1,
        )?;
        let iterations_count_key = get_string_at_offset(
            quick_idx_map,
            strings,
            "the force is not strong with this one",
            1,
        )?;
        let time_spent_key = get_string_at_offset(
            quick_idx_map,
            strings,
            "the force is not strong with this one",
            2,
        )?;
        let found_hash_key = get_string_at_offset(quick_idx_map, strings, "now##1", 1)?;

        Ok(Self {
            pow_string_key,
            pow_string_value,
            difficulty_key,
            difficulty,
            hash_key,
            hash_value,
            iterations_count_key,
            time_spent_key,
            result_key,
            found_hash_key,
        })
    }

    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        map.insert(
            self.pow_string_key.clone(),
            self.pow_string_value.clone().into(),
        );
        map.insert(self.difficulty_key.clone(), self.difficulty.into());
        map.insert(self.hash_key.clone(), self.hash_value.clone().into());

        let c_ray = &task.challenge_data.c_ray;
        let result = run_pow(
            c_ray,
            &self.pow_string_value,
            &self.hash_value,
            self.difficulty as usize,
            task.solve_start_time,
        )?;

        if let Some(hash) = result.hash {
            map.insert(self.found_hash_key.clone(), hash.into());
        }

        let time_spent = (result.iterations as f64) * 0.6;
        let time_spent_no_zeros = FloatWithoutZeros::new(imprecise_performance_now_value(time_spent));

        map.insert(self.result_key.clone(), result.result.into());
        map.insert(self.iterations_count_key.clone(), result.iterations.into());
        map.insert(self.time_spent_key.clone(), time_spent_no_zeros.into());

        Ok(time_spent as usize + rng().random_range(10..=30))
    }
}

#[derive(Debug)]
pub struct POWResult {
    pub result: String,
    pub hash: Option<String>,
    pub iterations: i32,
    pub time_spent: f64,
}

pub fn run_pow(
    c_ray: &str,
    string: &str,
    hash_to_achieve: &str,
    difficulty: usize,
    solve_start_time: &SystemTime,
) -> Result<POWResult, Error> {
    let start = SystemTime::now();

    let base = format!(
        "{}|{}|{}|",
        c_ray,
        performance_now(solve_start_time),
        difficulty
    );
    let mut iterations = 0;
    let mut rnd = ThreadRng::default().random_range(1..10000);

    loop {
        if start.elapsed().expect("time went backwards").as_secs() >= 20 {
            let spent =
                (start.elapsed().expect("time went backwards").as_micros() / 100) as f64 / 10.0;
            return Ok(POWResult {
                result: "the force is not strong with this one".to_string(),
                hash: None,
                iterations,
                time_spent: imprecise_performance_now_value(spent),
            });
        }

        let current = format!("{base}{rnd}");
        let mut hasher = Sha256::new();
        sha2::Digest::update(&mut hasher, format!("{current}{string}").as_bytes());
        let hash = hex::encode(hasher.finalize());
        iterations += 1;

        let is_valid = match hash_to_achieve.len().checked_sub(difficulty) {
            Some(start) => hash.ends_with(&hash_to_achieve[start..]),
            None => bail!("could not check if hash matches: {} {} {} {}", hash, hash_to_achieve, string, difficulty),
        };

        if is_valid {
            let spent =
                (start.elapsed().expect("time went backwards").as_micros() / 100) as f64 / 10.0;
            return Ok(POWResult {
                result: current,
                hash: Some(hash),
                iterations,
                time_spent: imprecise_performance_now_value(spent),
            });
        }

        rnd += 1;
    }
}

pub fn performance_now(time: &SystemTime) -> f64 {
    let duration = SystemTime::now()
        .duration_since(*time)
        .expect("Time went backwards");
    let millis = duration.as_secs() as f64 * 1_000.0 + duration.subsec_millis() as f64;
    let micros = duration.subsec_micros() as f64 % 1_000.0;
    let timestamp = millis + (micros / 1000.0);

    imprecise_performance_now_value((timestamp * 10.0).round() / 10.0)
}

#[cfg(test)]
mod tests {
    use crate::solver::entries::pow::run_pow;
    use sha2::Digest;
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_pow() {
        let hash_to_achieve = "d2ce9110f0fabbdb6047b60afddd753d937afdbdc9fd59f11ab1defb3b498da9";
        let string = "WKoMGZDcOHDLJeBoQUjlSiUylVyowZuxMTrgoKoVohzjDtrtVYQGIpDiyWGrqkQQEwHyeqeDXEjIRedhHTBjkOtlnfASGKczaoHhpLusAkDzIBMGdRYJVmLrauaxWdZz";
        let difficulty = 2;

        let result = run_pow(
            "93b9f6e07d3ebefa",
            string,
            hash_to_achieve,
            difficulty,
            &(SystemTime::now() - Duration::new(5, 43290239)),
        ).unwrap();
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(
            &mut hasher,
            format!("{}{}", result.result, string).as_bytes(),
        );
        let hash = hex::encode(hasher.finalize());

        dbg!(&hash);
        dbg!(&hash_to_achieve);
        assert!(hash.ends_with(&hash_to_achieve[hash_to_achieve.len() - difficulty..]));
    }
}