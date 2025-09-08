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
        )
            .unwrap();
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(
            &mut hasher,
            format!("{}{}", result.result, string).as_bytes(),
        );
        let hash = hex::encode(hasher.finalize());

        assert!(hash.ends_with(&hash_to_achieve[hash_to_achieve.len() - difficulty..]));
    }
}

use crate::solver::entries::pow::run_pow;
use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::utils::random_time;
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::{bail, Context, Error};
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{json, Map, Value};

#[derive(Clone, Debug)]
pub struct POWClickEntry {
    static_false_key: String,
    pow_string_key: String,
    pow_string_value: String,
    difficulty_key: String,
    difficulty: isize,
    click_data_key: String,
    time_until_click_key: String,
    hash_key: String,
    hash_value: String,
    result_key: String,
    found_hash_key: String,
    iterations_count_key: String,
    time_spent_key: String,

    unknown_string: String,
}

#[async_trait]
impl FingerprintEntryBase for POWClickEntry {
    fn parse(
        quick_idx_map: &FxHashMap<String, usize>,
        strings: &[String],
        values: &[VMEntryValue],
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let static_false_key = get_string_at_offset(quick_idx_map, strings, "performance", -6)?;
        let pow_string_key = get_string_at_offset(quick_idx_map, strings, "performance", -5)?;
        let pow_string_value = get_string_at_offset(quick_idx_map, strings, "performance", -4)?;
        let difficulty_key = get_string_at_offset(quick_idx_map, strings, "performance", -3)?;

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

        let click_data_key = get_string_at_offset(quick_idx_map, strings, "Error##1", -2)?;
        let time_until_click_key = get_string_at_offset(quick_idx_map, strings, "now##3", 1)?;

        let hash_key = get_string_at_offset(quick_idx_map, strings, "performance", -2)?;
        let hash_value = get_string_at_offset(quick_idx_map, strings, "performance", -1)?;

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
        let found_hash_key = get_string_at_offset(quick_idx_map, strings, "now##2", 2)?;

        let unknown_string = get_string_at_offset(quick_idx_map, strings, "Error", -1)?;
        Ok(Self {
            static_false_key,
            pow_string_key,
            pow_string_value,
            difficulty_key,
            difficulty,
            click_data_key,
            time_until_click_key,
            hash_key,
            hash_value,
            iterations_count_key,
            time_spent_key,
            result_key,
            found_hash_key,
            unknown_string,
        })
    }

    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        map.insert(self.static_false_key.clone(), false.into());
        map.insert(
            self.pow_string_key.clone(),
            self.pow_string_value.clone().into(),
        );
        map.insert(self.difficulty_key.clone(), self.difficulty.into());
        map.insert(self.hash_key.clone(), self.hash_value.clone().into());

        let func_with_opcodes = task
            .function_with_opcodes;

        let orchestrate_url = format!("https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/{}/orchestrate/chl_api/v1?ray={}&lang=auto", task.task_client.get_branch(), task.challenge_data.c_ray);

        let formatted_error = format!(
            "Error\n    at {}.{} ({}:1:49532)\n    at {}:1:55769\n    at {}:1:56624\n    at {}.{} ({}:1:56655)",
            func_with_opcodes,
            task.opcode_to_function_name.get("CallFuncNoContext")
                .expect("pow click entry: CallFuncNoContext opcode not found"),
            orchestrate_url,
            orchestrate_url,
            orchestrate_url,
            func_with_opcodes,
            task.create_function_ident,
            orchestrate_url,
        );

        let elapsed_ts = random_time(&mut rng(), 3000.0..5000.0);
        let ts = elapsed_ts.to_string();

        let click_data = [
            json!({
              "activeElement": "[object HTMLBodyElement]",
              "clientX": "24",
              "clientY": "27",
              "height": "1",
              "isPrimary": "false",
              "isTrusted": "true",
              "layerX": "7",
              "layerY": "6",
              "movementX": "0",
              "movementY": "0",
              "offsetX": "7",
              "offsetY": "7",
              "pageX": "24",
              "pageY": "27",
              "pointerId": "1",
              "pointerType": "mouse",
              "pressure": "0",
              "relatedTarget": "null",
              "screenX": "892",
              "screenY": "1831",
              "srcElement": "[object HTMLInputElement]",
              "tangentialPressure": "0",
              "target": "[object HTMLInputElement]",
              "timeStamp": ts,
              "type": "click",
              "width": "1",
              "x": "24",
              "y": "27"
            }),
            formatted_error.into(),
            self.unknown_string.clone().into(),
            false.into(),
        ];

        map.insert(
            self.click_data_key.clone(),
            task.encryption.encrypt(click_data.into()).into(),
        );

        let c_ray = &task.challenge_data.c_ray;
        let mut result = run_pow(
            c_ray,
            &self.pow_string_value,
            &self.hash_value,
            self.difficulty as usize,
            task.solve_start_time,
        )?;
        
        result.time_spent = (result.iterations as f64) * 0.6;

        map.insert(
            self.time_until_click_key.clone(),
            (elapsed_ts - result.time_spent).into(),
        );

        if let Some(hash) = result.hash {
            map.insert(self.found_hash_key.clone(), hash.into());
        }

        map.insert(self.result_key.clone(), result.result.into());
        map.insert(self.iterations_count_key.clone(), result.iterations.into());
        map.insert(self.time_spent_key.clone(), result.time_spent.into());

        Ok(elapsed_ts as usize + result.time_spent as usize + rng().random_range(10..=30))
    }
}
