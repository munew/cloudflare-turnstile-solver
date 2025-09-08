use crate::deobfuscator::deobfuscate;
use crate::disassembler::disassemble;
use crate::disassembler::instructions::{
    Instruction, LiteralInstructionType, RegisteredFunction, Value,
};
use crate::parser::payload::PayloadKeyExtractor;
use crate::reverse::compress::Compressor;
use crate::reverse::encryption::{decrypt_cloudflare_response, CloudflareXorEncryption};
use crate::solver::challenge::CloudflareChallengeOptions;
use crate::solver::keys::InitPayloadKeys;
use crate::solver::performance::{Performance, PerformanceEntry, PerformanceVisibilityStateEntry};
use crate::solver::task_client::TaskClient;
use crate::solver::user_fingerprint::{Fingerprint, FloatWithoutZeros};
use crate::solver::utils::{diff, imprecise_performance_now_value, random_time};
use crate::solver::vm_parser::{ParsedVM, TurnstileTaskEntryContext, VMFingerprintParser};
use anyhow::{anyhow, bail, Context};
use oxc_allocator::Allocator;
use rand::{random_range, rng};
use rustc_hash::FxHashMap;
use serde_json::json;
use std::iter::repeat_n;
use std::time::SystemTime;
use url::Url;
use uuid::Uuid;

pub struct TurnstileTask<'a> {
    site_key: String,
    action: Option<String>,
    cdata: Option<String>,
    page_data: Option<String>,
    task_client: TaskClient,
    referrer: String,
    fingerprint: &'a Fingerprint,
    solve_start_time: SystemTime,
    browser_cf_keys: Vec<String>,
    performance: Performance,
    query_selector_calls: Vec<String>,
}

#[derive(Debug)]
pub struct TurnstileSolveResult {
    pub token: String,
    pub interactive: bool,
}

impl<'a> TurnstileTask<'a> {
    pub fn new(
        site_key: String,
        referrer: String,
        action: Option<String>,
        cdata: Option<String>,
        page_data: Option<String>,
        fingerprint: &'a Fingerprint,
    ) -> Result<Self, anyhow::Error> {
        let task_client = TaskClient::new(
            referrer.clone(),
            fingerprint.headers.clone(),
        )?;

        Ok(Self {
            task_client,
            action,
            cdata,
            page_data,
            site_key,
            referrer,
            fingerprint,
            browser_cf_keys: Vec::new(),
            solve_start_time: SystemTime::now(),
            performance: Performance::default(),
            query_selector_calls: Vec::new(),
        })
    }

    pub async fn solve(&mut self) -> Result<TurnstileSolveResult, anyhow::Error> {
        self.performance
            .add_entry(PerformanceEntry::VisibilityState(
                PerformanceVisibilityStateEntry {
                    r#type: "v".to_string(),
                    start_time: 0,
                    duration: 0,
                },
            ));

        let allocator = Allocator::new();
        let timezone = self.task_client.get_timezone().await?;
        let turnstile_load_init_time_ms = SystemTime::now();
        
        let version_info = self.task_client.get_api().await?;

        let (solve_url, _, challenge_data) =
            self.task_client.initialize_solve(&self.site_key).await?;

        self.query_selector_calls
            .extend(repeat_n("window.frameElement".to_string(), 3));

        self.performance.add_entry(
            self.task_client
                .get_random_image(&challenge_data.zone)
                .await?,
        );

        let (orchestrate_perf, orchestrate_js) = self
            .task_client
            .get_orchestrate(&challenge_data.zone, &challenge_data.c_ray)
            .await?;

        self.performance.add_entry(orchestrate_perf);
        

        let solve_language = orchestrate_js
            .split("\"lang\":\"")
            .nth(1)
            .context("could not find language in orchestrate script")?
            .split("\"")
            .nth(0)
            .context("could not find language in orchestrate script")?
            .to_string();

        let orchestrate_program = deobfuscate(&orchestrate_js, &allocator, true);

        let (
            mut disassembler,
            extracted_script,
            extracted_keys,
            create_function_ident,
            function_with_opcodes,
            opcode_to_function_name,
        ) = disassemble::parse_script_interpreter(orchestrate_program, &allocator)?;

        self.browser_cf_keys.extend([
            extracted_keys.initial_keys[16].to_string(),
            extracted_keys.initial_keys[14].to_string(),
            extracted_keys.browser_keys_key.to_string(),
        ]);

        let compressor = Compressor::new(
            extracted_script
                .compressor_charset
                .unwrap()
        );

        let init_keys = InitPayloadKeys::new(extracted_keys.initial_keys.clone());
        let init_payload = self.build_init_payload(
            &challenge_data,
            &init_keys,
            &extracted_keys,
            &version_info.version,
            turnstile_load_init_time_ms,
        )?;

        let compressed_init_payload = compressor.compress(&serde_json::to_string(&init_payload)?);

        let (post_init_perf, encrypted_main_vm) = self
            .task_client
            .post_init_payload(
                compressed_init_payload,
                challenge_data.zone.as_str(),
                extracted_script.init_argument.unwrap().as_str(),
                challenge_data.c_ray.as_str(),
                challenge_data.ch.as_str(),
            )
            .await?;
        self.performance.add_entry(post_init_perf);

        let main_vm =
            decrypt_cloudflare_response(&challenge_data.c_ray, encrypted_main_vm.as_str())?;

        let (base_instructions, functions) = disassembler.read_encoded_vm(main_vm.as_str())?;

        let (encryption, cray_key) = self.build_encryption(&functions, &challenge_data.c_ray)?;

        let parsed_vm = self.parse_vm(&base_instructions, &functions)?;
        let (mut payload, url) = self
            .build_second_payload(
                &parsed_vm,
                &init_payload,
                &init_keys,
                &functions,
                &compressor,
                &encryption,
                &challenge_data,
                solve_url.as_str(),
                solve_language.as_str(),
                timezone.as_str(),
                &opcode_to_function_name,
                create_function_ident.as_str(),
                function_with_opcodes.as_str(),
                &cray_key,
            )
            .await?;

        let compressed_second_payload = compressor.compress(&serde_json::to_string(&payload)?);

        let output = self
            .task_client
            .post_payload(
                &url,
                compressed_second_payload,
                &challenge_data.ch,
                &challenge_data.c_ray,
            )
            .await?;

        let (base_instructions, final_functions) = disassembler.read_encoded_vm(output.as_str())?;

        let mut turnstile_result = extract_turnstile_result(&final_functions);

        if turnstile_result.flagged {
            bail!("turnstile flagged");
        }

        let mut is_interactive = false;
        if turnstile_result.token.is_none()
            && challenge_data.c_type == "chl_api_m"
            && challenge_data.api_mode == "managed"
        {
            is_interactive = true;

            let current_entries_count = payload
                .get(init_keys.payload_entries_count.as_str())
                .unwrap()
                .as_i64()
                .unwrap() as usize;
            payload.insert(
                init_keys.prev_payload_entries_count.clone(),
                current_entries_count.into(),
            );

            let parsed_vm = self.parse_vm(&base_instructions, &final_functions)?;
            payload.insert(
                init_keys.payload_entries_count.clone(),
                (current_entries_count + parsed_vm.entries.len()).into(),
            );

            let mut ctx = TurnstileTaskEntryContext {
                compressor: &compressor,
                encryption: &encryption,
                performance: &mut self.performance,
                task_client: &mut self.task_client,
                solve_url: solve_url.as_str(),
                solve_language: solve_language.as_str(),
                fingerprint: &self.fingerprint,
                referrer: &self.referrer,
                query_selector_calls: &mut self.query_selector_calls,
                challenge_data: &challenge_data,
                timezone: timezone.as_str(),
                solve_start_time: &self.solve_start_time,
                browser_cf_keys: &self.browser_cf_keys,
                opcode_to_function_name: &opcode_to_function_name,
                create_function_ident: &create_function_ident,
                function_with_opcodes: &function_with_opcodes,
            };

            for (i, entry) in parsed_vm.entries.iter().enumerate() {
                let value = parsed_vm.make_vm_payload_entry(&mut ctx, entry).await?;
                payload.shift_insert(
                    current_entries_count,
                    (current_entries_count + i + 1).to_string(),
                    value,
                );
            }

            let mut last_entry_keys = parsed_vm.last_entry_strings;

            let array_parameters_key = last_entry_keys.remove(0);
            let mut arr = Vec::new();
            while last_entry_keys[0].contains("_") || last_entry_keys[0].len() < 4 {
                arr.push(last_entry_keys.remove(0));
            }
            payload.insert(array_parameters_key, arr.into());

            payload.insert(last_entry_keys.remove(0), last_entry_keys.remove(0).into());
            last_entry_keys.remove(0);
            payload.insert(last_entry_keys.remove(0), last_entry_keys.remove(0).into());

            let post_url_path = last_entry_keys
                .iter()
                .find(|s| s.starts_with("flow/"))
                .unwrap()
                .clone();

            let compressed_third_payload = compressor.compress(&serde_json::to_string(&payload)?);

            let result = self
                .task_client
                .post_payload(
                    format!(
                        "https://{}/cdn-cgi/challenge-platform/h/{}/{}",
                        challenge_data.zone,
                        self.task_client.get_branch(),
                        post_url_path,
                    )
                    .as_str(),
                    compressed_third_payload,
                    &challenge_data.ch,
                    &challenge_data.c_ray,
                )
                .await?;

            let (_, final_functions) = disassembler.read_encoded_vm(result.as_str())?;

            turnstile_result = extract_turnstile_result(&final_functions);
        }

        if turnstile_result.flagged {
            bail!("interactive turnstile flagged");
        }

        Ok(TurnstileSolveResult {
            interactive: is_interactive,
            token: turnstile_result.token.unwrap(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_second_payload(
        &mut self,
        parsed_vm: &ParsedVM,
        init_payload: &serde_json::Map<String, serde_json::Value>,
        init_keys: &InitPayloadKeys,
        functions: &FxHashMap<usize, RegisteredFunction>,
        compressor: &Compressor,
        encryption: &CloudflareXorEncryption,
        challenge_opt: &CloudflareChallengeOptions,
        solve_url: &str,
        solve_language: &str,
        timezone: &str,
        opcode_to_function_name: &FxHashMap<String, String>,
        create_function_ident: &str,
        function_with_opcodes: &str,
        cray_key: &str,
    ) -> Result<(serde_json::Map<String, serde_json::Value>, String), anyhow::Error> {
        let mut payload = serde_json::Map::new();

        {
            let mut ctx = TurnstileTaskEntryContext {
                compressor,
                encryption,
                performance: &mut self.performance,
                task_client: &mut self.task_client,
                solve_url,
                solve_language,
                fingerprint: self.fingerprint,
                referrer: &self.referrer,
                query_selector_calls: &mut self.query_selector_calls,
                challenge_data: challenge_opt,
                timezone,
                solve_start_time: &self.solve_start_time,
                browser_cf_keys: &self.browser_cf_keys,
                opcode_to_function_name,
                create_function_ident,
                function_with_opcodes,
            };

            for (i, entry) in parsed_vm.entries.iter().enumerate() {
                let value = parsed_vm.make_vm_payload_entry(&mut ctx, entry).await?;
                payload.insert((i + 1).to_string(), value);
            }
        }

        // Put additional entries inside the init payload like the VM does.
        self.add_init_entries_like_vm(
            &init_keys,
            init_payload,
            &mut payload,
            functions,
            &init_keys.unknown_5,
            challenge_opt.c_ray.as_str(),
            cray_key,
        )?;

        let worker_blob_key: Option<String> = self.find_worker_blob_key(functions);
        let mut worker_blob_object: Option<String> = None;
        let mut url_query: Option<String> = None;

        let mut last_entry_strings = parsed_vm.last_entry_strings.clone();
        for (i, string) in last_entry_strings.iter().enumerate() {

            if string == "terminate" {
                worker_blob_object = Some(last_entry_strings[i - 1].clone());
            }

            if string.starts_with("flow") {
                url_query = Some(string.clone());
            }
        }

        payload.remove(&init_keys.chl_dyn_key_2).unwrap();

        if worker_blob_key.is_none() {
            bail!("could not find worker blob key");
        }

        if worker_blob_object.is_none() {
            bail!("could not find worker blob array");
        }

        // replace current payload entries count (was 0)
        payload.insert(
            init_keys.payload_entries_count.clone(),
            parsed_vm.entries.len().into(),
        );

        let chl_dyn_key = payload.get(&init_keys.chl_dyn_key).unwrap().clone();
        insert_value_at_end(
            &mut payload,
            init_keys.turnstile_u.clone(),
            challenge_opt.turnstile_u.clone().into(),
        );
        insert_value_at_end(&mut payload, init_keys.chl_dyn_key.clone(), chl_dyn_key);

        insert_value_at_end(
            &mut payload,
            init_keys.encrypted_entry.clone(),
            encryption
                .encrypt(json!([
                    serde_json::Value::Null,
                    serde_json::Value::String("closed".to_string()),
                    serde_json::Value::String("<body></body>".to_string()),
                    serde_json::Value::String("".to_string()),
                    serde_json::Value::Number(4.into()),
                    serde_json::Value::Number(4.into()),
                    serde_json::Value::Number(37.into()),
                    serde_json::Value::String(
                        "function attachShadow() { [native code] }".to_string()
                    ),
                ]))
                .into(),
        );

        insert_value_at_end(
            &mut payload,
            worker_blob_key.unwrap(),
            format!("blob:https://{}/{}", challenge_opt.zone, Uuid::new_v4()).into(),
        );
        insert_value_at_end(
            &mut payload,
            worker_blob_object.unwrap(),
            serde_json::Value::Object(serde_json::Map::new()),
        );

        let array_parameters_key = last_entry_strings.remove(0);
        let mut arr = Vec::new();
        while last_entry_strings[0].contains("_") || last_entry_strings[0].len() < 4 {
            arr.push(last_entry_strings.remove(0));
        }
        insert_value_at_end(&mut payload, array_parameters_key, arr.into());

        insert_value_at_end(
            &mut payload,
            last_entry_strings.remove(0),
            last_entry_strings.remove(0).into(),
        ); // insert sort of id
        payload.insert(last_entry_strings.remove(0), 0.into()); // re-apply 0 value
        insert_value_at_end(
            &mut payload,
            last_entry_strings.remove(0),
            last_entry_strings.remove(0).into(),
        ); // insert unk

        last_entry_strings = last_entry_strings
            .into_iter()
            .filter(|k| k != "chlApiTimeoutEncountered" && k != "_cf_chl_opt")
            .collect();

        last_entry_strings.remove(0);
        last_entry_strings.remove(0);
        last_entry_strings.remove(0);

        // solves count on the same script??
        insert_value_at_end(&mut payload, last_entry_strings.remove(0), 0.into());

        // query selector calls
        last_entry_strings.remove(0); // pop
        insert_value_at_end(
            &mut payload,
            last_entry_strings.remove(0),
            serde_json::to_value(&self.query_selector_calls)?,
        );

        // pop twice useless keys
        last_entry_strings.remove(0);
        last_entry_strings.remove(0);

        // weird post message cray ping/pong value
        last_entry_strings.remove(0);
        insert_value_at_end(&mut payload, last_entry_strings.remove(0), 0.into());

        Ok((
            payload,
            format!(
                "https://{}/cdn-cgi/challenge-platform/h/{}/{}",
                challenge_opt.zone,
                self.task_client.get_branch(),
                url_query.context("expected challenge path")?
            ),
        ))
    }

    fn find_worker_blob_key(&self, functions: &FxHashMap<usize, RegisteredFunction>) -> Option<String> {
        for f in functions.values() {
            if !f.values.contains(&Value::String("script error".to_string())) {
                continue;
            }

            let pos = f.values.iter().position(|k| k == &Value::String("revokeObjectURL".to_string())).map(|i| match &f.values[i+1] {
                Value::String(s) => s.clone(),
                _ => unreachable!(),
            });

            return pos;
        }

        None
    }

    fn add_init_entries_like_vm(
        &self,
        init_payload_keys: &InitPayloadKeys,
        init_payload: &serde_json::Map<String, serde_json::Value>,
        payload: &mut serde_json::Map<String, serde_json::Value>,
        functions: &FxHashMap<usize, RegisteredFunction>,
        unknown_5_key: &str,
        c_ray: &str,
        cray_key: &str,
    ) -> Result<(), anyhow::Error> {
        let build_function = functions
            .iter()
            .find(|(_, k)| k.values.contains(&Value::String("chlApiSitekey".to_string())))
            .context("could not find the function that sets init entries")?
            .1;
        let mut index_map: FxHashMap<String, usize> = FxHashMap::default();

        for (i, v) in build_function.values.iter().enumerate() {
            if let Value::String(s) = v {
                index_map.insert(s.clone(), i);
            }
        }

        let weird_key = match build_function
            .values
            .get(*index_map.get("md").unwrap() + 3)
            .unwrap()
        {
            Value::String(s) => s.clone(),
            _ => unreachable!(),
        };

        for (k, v) in init_payload {
            if *k == weird_key {
                continue;
            }

            if *k == unknown_5_key {
                payload.insert(weird_key.clone(), 1.into());
                continue;
            }

            payload.insert(k.clone(), v.clone());

            if *k == init_payload_keys.c_type {
                payload.insert(cray_key.to_string(), c_ray.to_string().into());
            }
        }

        Ok(())
    }

    pub fn build_init_payload(
        &self,
        chl_opt: &CloudflareChallengeOptions,
        keys: &InitPayloadKeys,
        extractor: &PayloadKeyExtractor,
        ch_version: &str,
        turnstile_load_init_time_ms: SystemTime,
    ) -> Result<serde_json::Map<String, serde_json::Value>, anyhow::Error> {
        let mut map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

        let values = &extractor.initial_keys_values;
        let obj = extractor
            .initial_obj_keys
            .iter()
            .map(|key| (key.clone(), 0_i32.into()))
            .collect::<serde_json::Map<String, serde_json::Value>>();

        let mut rng = rng();

        let perf_1 = FloatWithoutZeros::new(diff(&mut rng, 10.0..20.0, 0.0..1.0));
        let perf_2 = FloatWithoutZeros::new(diff(&mut rng, 2.0..3.0, 0.0..1.0));
        let turnstile_age = FloatWithoutZeros::new(imprecise_performance_now_value(
            turnstile_load_init_time_ms.elapsed()?.as_millis() as f64 + random_range(200.0..400.0),
        ));

        let widget_age = FloatWithoutZeros::new(random_time(
            &mut rng,
            turnstile_age.value - 5.0..turnstile_age.value - 2.0,
        ));

        let time_to_params_ms = FloatWithoutZeros::new(random_time(&mut rng, 1.2..3.4));
        let time_to_render_ms = FloatWithoutZeros::new(random_time(&mut rng, 1.5..3.0));
        let tief_time_ms = FloatWithoutZeros::new(random_time(&mut rng, 0.2..0.4));
        let perf_3 = FloatWithoutZeros::new(diff(&mut rng, 2.0..3.0, 0.0..1.0));
        let perf_4 = random_time(&mut rng, perf_1.value + 0.2..perf_1.value + 0.5);
        let time_to_init_ms = FloatWithoutZeros::new(random_time(
            &mut rng,
            widget_age.value - 4.0..widget_age.value - 2.0,
        ));

        map.insert(keys.c_type.clone(), chl_opt.c_type.clone().into());
        map.insert(keys.cv_id.clone(), chl_opt.cv_id.clone().into());
        map.insert(keys.payload_entries_count.clone(), 0.into());
        map.insert(keys.prev_payload_entries_count.clone(), 0.into());
        map.insert(keys.perf_1.clone(), perf_1.clone().into());
        // dbg!(perf_2.value);
        map.insert(keys.perf_2.clone(), perf_2.into());
        map.insert(keys.unknown_3.clone(), 1.into());
        map.insert(keys.time.clone(), chl_opt.time.clone().into());
        map.insert(keys.md.clone(), chl_opt.md.clone().into());
        map.insert(keys.user_input.clone(), obj.into());

        map.insert(
            keys.chl_dyn_key.clone(),
            values.get(&keys.chl_dyn_key).unwrap().clone().into(),
        );
        map.insert(keys.encrypted_entry.clone(), String::new().into());
        map.insert(keys.empty_array.clone(), json!([]));
        map.insert(keys.unknown_5.clone(), 0.into());
        map.insert(
            keys.chl_dyn_key_2.clone(),
            values.get(&keys.chl_dyn_key_2).unwrap().clone().into(),
        );
        map.insert(keys.v_id.clone(), chl_opt.api_v_id.clone().into());
        map.insert(keys.site_key.clone(), self.site_key.clone().into());

        if let Some(action) = &self.action {
            map.insert(keys.action.clone(), action.clone().into());
        }

        if let Some(cdata) = &self.cdata {
            map.insert(keys.c_data.clone(), cdata.clone().into());
        }

        if let Some(page_data) = &self.page_data {
            map.insert(keys.page_data.clone(), page_data.clone().into());
        }

        map.insert(keys.timeout_encountered.clone(), 0.into());
        map.insert(keys.acch.clone(), ch_version.into());
        map.insert(
            keys.u.clone(),
            format!(
                "https://{}/turnstile/v0/api.js?onload=onloadTurnstileCallback",
                chl_opt.zone
            )
            .into(),
        );
        map.insert(keys.url.clone(), self.referrer.clone().into());
        map.insert(keys.origin.clone(), self.get_origin()?.into());
        map.insert(keys.rc_v.clone(), chl_opt.api_rcv.clone().into());
        map.insert(keys.reset_src.clone(), chl_opt.reset_src.clone().into());
        map.insert(keys.turnstile_age.clone(), turnstile_age.into());
        map.insert(keys.widget_age.clone(), widget_age.into());
        map.insert(keys.upgrade_attempts.clone(), 0.into());
        map.insert(keys.upgrade_completed_count.clone(), 0.into());
        map.insert(keys.time_to_init_ms.clone(), time_to_init_ms.into());
        map.insert(keys.time_to_render_ms.clone(), time_to_render_ms.into());
        map.insert(keys.time_to_params_ms.clone(), time_to_params_ms.into());
        map.insert(keys.perf_3.clone(), perf_3.into());
        map.insert(keys.perf_4.clone(), FloatWithoutZeros::new(perf_4).into());
        map.insert(keys.tief_time_ms.clone(), tief_time_ms.into());
        map.insert(keys.turnstile_u.clone(), chl_opt.turnstile_u.clone().into());

        Ok(map)
    }

    fn parse_vm(
        &mut self,
        base_instructions: &Vec<(usize, Instruction)>,
        functions: &FxHashMap<usize, RegisteredFunction>,
    ) -> Result<ParsedVM, anyhow::Error> {
        let cff_function = functions
            .iter()
            .find(|(_, k)| {
                k.values
                    .contains(&Value::String("life goes on".to_string()))
            })
            .context("could not find the function that builds payload")?
            .1;

        let parser =
            VMFingerprintParser::new(base_instructions, functions, cff_function.start as usize);

        parser.parse_vm()
    }

    fn build_encryption(
        &self,
        functions: &FxHashMap<usize, RegisteredFunction>,
        c_ray: &str,
    ) -> Result<(CloudflareXorEncryption, String), anyhow::Error> {
        let func = functions
            .iter()
            .find(|f| {
                f.1.values
                    .contains(&Value::String("TextEncoder".to_string()))
            })
            .ok_or_else(|| anyhow!("could not find encryption function"))?
            .1;

        if let Some(Value::String(s)) = func.values.get(2) {
            let enc = CloudflareXorEncryption::new(s.as_str(), c_ray);
            Ok((
                enc,
                func.values.get(0).unwrap().as_string().unwrap().clone(),
            ))
        } else {
            Err(anyhow!("could not find encryption key in enc function"))
        }
    }

    fn get_origin(&self) -> Result<String, anyhow::Error> {
        let parsed = Url::parse(self.referrer.as_str())?;
        Ok(parsed.origin().ascii_serialization())
    }
}

fn insert_value_at_end(
    map: &mut serde_json::Map<String, serde_json::Value>,
    key: String,
    new_value: serde_json::Value,
) {
    map.shift_remove(&key);
    map.insert(key, new_value);
}

struct TurnstileResult {
    flagged: bool,
    token: Option<String>,
}

fn extract_turnstile_result(functions: &FxHashMap<usize, RegisteredFunction>) -> TurnstileResult {
    let mut token: Option<String> = None;
    let mut is_flagged = false;

    'loo: for (_, f) in functions.iter() {
        for (_, i) in f.body.iter() {
            if let Instruction::NewLiteral(lit) = i
                && let LiteralInstructionType::String(s) = &lit.data
            {
                if s.starts_with("0.") {
                    token = Some(s.clone());
                    break 'loo;
                } else if s == "600010" {
                    is_flagged = true;
                    break 'loo;
                }
            }
        }
    }

    TurnstileResult {
        flagged: is_flagged,
        token,
    }
}
