use crate::decompiler::flow::analysis::{ControlFlowAnalysis, FlowStructure};
use crate::decompiler::flow::{BasicBlock, ControlFlowGraph, NodeId};
use crate::disassembler::instructions::{
    Instruction, LiteralInstructionType, RegisteredFunction, UsedRegisters,
};
use crate::parser::magic_bits::BinaryOperator;
use crate::reverse::compress::Compressor;
use crate::reverse::encryption::CloudflareXorEncryption;
use crate::solver::challenge::CloudflareChallengeOptions;
use crate::solver::entries::audio::AudioEntry;
use crate::solver::entries::browser_data::BrowserDataEntry;
use crate::solver::entries::browser_keys::BrowserKeysEntry;
use crate::solver::entries::computed_style::ComputedStyleEntry;
use crate::solver::entries::css::CssEntry;
use crate::solver::entries::div_render_time::DivRenderTimeEntry;
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
use crate::solver::entries::pow_click::POWClickEntry;
use crate::solver::entries::selenium::SeleniumEntry;
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
use crate::solver::entries::{FingerprintEntry, FingerprintEntryBase};
use crate::solver::performance::Performance;
use crate::solver::task_client::TaskClient;
use crate::solver::user_fingerprint::Fingerprint;
use anyhow::{anyhow, bail, Context};
use once_cell::sync::Lazy;
use rustc_hash::{FxHashMap, FxHashSet};
use serde_json::Number;
use std::collections::{HashSet, VecDeque};
use std::time::SystemTime;

#[derive(Debug)]
pub struct VMPayloadEntryCase {
    pub id: String,
    pub unknown: String,
    pub unknown_2: String,

    pub _type: FingerprintEntry,
}

impl VMPayloadEntryCase {
    pub fn generate_parse_status(&self) -> i32 {
        // 0 = init, 1 = collecting, 2 = collecting stage 2, 3 = success,
        // however, it seems like that on pc none fails, so we just put success for every of them
        3
    }
}

#[derive(Debug)]
pub struct ParsedVM {
    pub entries: Vec<VMPayloadEntryCase>,
    pub last_entry_strings: Vec<String>,
    pub fp_id_key: String,
    pub fp_unknown_key: String,
    pub fp_unknown_2_key: String,
    pub fp_stage_key: String,
    pub fp_time_taken_key: String,
}

pub struct TurnstileTaskEntryContext<'a> {
    pub compressor: &'a Compressor,
    pub encryption: &'a CloudflareXorEncryption,
    pub solve_language: &'a str,
    pub solve_url: &'a str,
    pub performance: &'a mut Performance,
    pub task_client: &'a mut TaskClient,
    pub fingerprint: &'a Fingerprint,
    pub referrer: &'a str,
    pub query_selector_calls: &'a mut Vec<String>,
    pub challenge_data: &'a CloudflareChallengeOptions,
    pub timezone: &'a str,
    pub solve_start_time: &'a SystemTime,
    pub browser_cf_keys: &'a Vec<String>,
    pub opcode_to_function_name: &'a FxHashMap<String, String>,
    pub create_function_ident: &'a str,
    pub function_with_opcodes: &'a str,
}

impl ParsedVM {
    pub async fn make_vm_payload_entry<'a>(
        &self,
        task: &mut TurnstileTaskEntryContext<'a>,
        entry: &VMPayloadEntryCase,
    ) -> Result<serde_json::Value, anyhow::Error> {
        let mut map = serde_json::Map::new();

        map.insert(self.fp_id_key.clone(), entry.id.clone().into());
        map.insert(self.fp_unknown_key.clone(), entry.unknown.clone().into());

        map.insert(
            self.fp_unknown_2_key.clone(),
            entry.unknown_2.clone().into(),
        );

        map.insert(
            self.fp_time_taken_key.clone(),
            serde_json::Value::Number(Number::from(0)),
        );

        map.insert(
            self.fp_stage_key.clone(),
            entry.generate_parse_status().into(),
        );

        let timing = entry
            ._type
            .as_entry_base()
            .write_entry(task, &mut map)
            .await?;

        // tokio::time::sleep(std::time::Duration::from_millis(timing as u64)).await;

        map.insert(
            self.fp_time_taken_key.clone(),
            serde_json::Value::Number(Number::from(timing)),
        );

        Ok(map.into())
    }
}

pub struct VMFingerprintParser<'a> {
    functions: &'a FxHashMap<usize, RegisteredFunction>,
    function_start: usize,
    base_instructions: &'a Vec<(usize, Instruction)>,
}

#[derive(Debug)]
pub enum VMEntryValue<'a> {
    String(&'a str),
    Integer(isize),
}

impl<'a> VMFingerprintParser<'a> {
    pub fn new(
        base_instructions: &'a Vec<(usize, Instruction)>,
        functions: &'a FxHashMap<usize, RegisteredFunction>,
        function_start: usize,
    ) -> Self {
        Self {
            functions,
            function_start,
            base_instructions,
        }
    }

    pub fn parse_vm(&self) -> Result<ParsedVM, anyhow::Error> {
        let main_func = self.functions.get(&self.function_start).unwrap();
        let cfg = ControlFlowGraph::make(self.function_start, main_func.body.clone());

        let (mut keys_order, key_to_instructions) = self.grab_keys_order(&cfg)?;
        keys_order.pop_front(); // remove __undefined key which is basically the start entry and contains nothing useful

        let last_key = keys_order.pop_back().context("expected a key")?;

        let static_registers = self.get_static_registers(&cfg.blocks[&self.function_start]);
        let (entries, fp_id_key, fp_unknown_key, fp_unknown_2_key, fp_stage_key, fp_time_taken_key) =
            self.extract_entries(&keys_order, &key_to_instructions, &static_registers)?;

        let last_entry_instructions = key_to_instructions
            .get(&last_key)
            .context("expected key instructions")?;
        let mut last_entry_strings = Vec::new();

        for instruction in last_entry_instructions {
            for x in instruction.get_used_registers() {
                if let Some(s) = static_registers.get(&x) {
                    last_entry_strings.push(s.clone());
                }
            }
            if let Instruction::NewLiteral(lit) = instruction
                && let LiteralInstructionType::String(s) = &lit.data
            {
                last_entry_strings.push(s.clone());
            }
        }

        // println!(
        //     "Took {} micro-seconds to parse VM",
        //     time.elapsed().as_micros()
        // );

        Ok(ParsedVM {
            entries,
            fp_id_key,
            last_entry_strings,
            fp_unknown_key,
            fp_unknown_2_key,
            fp_stage_key,
            fp_time_taken_key,
        })
    }

    fn extract_entries(
        &self,
        keys_order: &VecDeque<String>,
        key_to_instructions: &FxHashMap<String, Vec<Instruction>>,
        static_registers: &FxHashMap<u16, String>,
    ) -> Result<
        (
            Vec<VMPayloadEntryCase>,
            String,
            String,
            String,
            String,
            String,
        ),
        anyhow::Error,
    > {
        let mut fp_id_key: Option<String> = None;
        let mut fp_unknown_key: Option<String> = None;
        let mut fp_unknown_2_key: Option<String> = None;
        let mut fp_stage_key: Option<String> = None;
        let mut fp_time_taken_key: Option<String> = None;

        let mut entries: Vec<VMPayloadEntryCase> = Vec::new();

        let mut current_id: Option<String> = None;
        let mut current_unknown: Option<String> = None;
        let mut current_unknown_2: Option<String> = None;
        
        for (i, key) in keys_order.iter().enumerate() {
            let instructions = key_to_instructions.get(key).unwrap();

            match i % 3 {
                0 => {
                    let mut found_strings = Vec::new();

                    for instruction in instructions {
                        if let Instruction::NewLiteral(op) = instruction
                            && let LiteralInstructionType::String(s) = &op.data
                        {
                            found_strings.push(s.clone());
                        }

                        if let Instruction::SetProperty(prop) = instruction
                            && let Some(value) = static_registers.get(&prop.val_reg)
                        {
                            found_strings.push(value.clone());
                        }
                    }

                    if found_strings.len() < 8 {
                        bail!("expected at least seven strings in CFF case. strings: {:?}", found_strings);
                    }
                    if found_strings[7] != "getTime" && found_strings[7] != "Date" {
                        bail!(
                            "expected specific string at strings[7]. Strings: {:?}",
                            found_strings
                        );
                    }

                    if fp_id_key.is_none() {
                        fp_id_key = Some(found_strings[0].clone());
                        fp_unknown_key = Some(found_strings[2].clone());
                        fp_unknown_2_key = Some(found_strings[4].clone());
                        fp_time_taken_key = Some(found_strings[6].clone());
                    } else if fp_id_key.as_ref().unwrap() != &found_strings[0]
                        || fp_unknown_key.as_ref().unwrap() != &found_strings[2]
                        || fp_unknown_2_key.as_ref().unwrap() != &found_strings[4]
                        || fp_time_taken_key.as_ref().unwrap() != &found_strings[6]
                    {
                        bail!(
                            "expected same keys as previous entry. Strings: {:?}",
                            found_strings
                        );
                    }

                    current_id = Some(found_strings[1].clone());
                    current_unknown = Some(found_strings[3].clone());
                    current_unknown_2 = Some(found_strings[5].clone());
                }
                1 => {
                    let function_id = instructions
                        .iter()
                        .find_map(|instruction| {
                            if let Instruction::RegisterVMFunc(op) = instruction {
                                Some(op.jump.pos)
                            } else {
                                None
                            }
                        })
                        .ok_or_else(|| anyhow!("could not find function id"))?;

                    let (strings, values) =
                        self.collect_strings_and_values(function_id, &mut FxHashSet::default());
                    let quick_map_idx = Self::build_quick_idx_map(&strings);

                    if let Some(map_res) =
                        self.map_fingerprinting_cases(&strings, &values, &quick_map_idx)
                    {
                        let mapped = map_res?;
                        
                        if fp_stage_key.is_none()
                            && (matches!(&mapped, FingerprintEntry::StaticValue(_))
                                || matches!(&mapped, FingerprintEntry::POWClick(_)))
                        {
                            fp_stage_key = self.find_fp_stage(
                                &self.functions.get(&function_id).unwrap().body,
                                matches!(&mapped, FingerprintEntry::POWClick(_)),
                            );
                        }

                        entries.push(VMPayloadEntryCase {
                            id: current_id.take().unwrap(),
                            unknown: current_unknown.take().unwrap(),
                            unknown_2: current_unknown_2.take().unwrap(),
                            _type: mapped,
                        });
                    } else {
                        bail!("Could not map entry. Strings: {:?}", strings);
                    }
                }
                2 => {}
                _ => unreachable!(),
            }
        }

        Ok((
            entries,
            fp_id_key.unwrap(),
            fp_unknown_key.unwrap(),
            fp_unknown_2_key.unwrap(),
            fp_stage_key.unwrap(),
            fp_time_taken_key.unwrap(),
        ))
    }

    fn find_fp_stage(
        &self,
        instructions: &[(usize, Instruction)],
        is_interactive: bool,
    ) -> Option<String> {
        let mut collected_string_registers = FxHashMap::default();
        for (_, instruction) in self.base_instructions {
            if let Instruction::NewLiteral(lit) = instruction
                && let LiteralInstructionType::String(s) = &lit.data
            {
                collected_string_registers.insert(lit.ret_reg, s.clone());
            }
        }

        for (idx, (_, instruction)) in instructions.iter().enumerate() {
            if let Instruction::NewLiteral(lit) = instruction
                && let LiteralInstructionType::Byte(b) = &lit.data
                && ((!is_interactive && *b == 3) || (is_interactive && *b == 2))
                && let Some((_, next_instruction)) = instructions.get(idx + 1)
                && let Instruction::SetProperty(prop) = next_instruction
                && prop.val_reg == lit.ret_reg
                && collected_string_registers.contains_key(&prop.key_reg)
            {
                return Some(
                    collected_string_registers
                        .get(&prop.key_reg)
                        .unwrap()
                        .clone(),
                );
            }
        }

        None
    }

    fn get_static_registers(&self, bb: &BasicBlock) -> FxHashMap<u16, String> {
        let mut static_registers: FxHashMap<u16, String> = FxHashMap::default();

        for instruction in &bb.instructions {
            if let Instruction::NewLiteral(lit) = instruction
                && let LiteralInstructionType::String(s) = &lit.data
                && s != "life goes on"
            {
                static_registers.insert(lit.ret_reg, s.clone());
            }
        }

        static_registers
    }

    fn build_quick_idx_map(v: &Vec<String>) -> FxHashMap<String, usize> {
        let mut quick_idx_map = FxHashMap::with_capacity_and_hasher(v.len(), Default::default());

        for (i, str) in v.iter().enumerate() {
            if quick_idx_map.get(str).is_some() {
                let mut idx = 1;
                let mut key = String::with_capacity(str.len() + 5);

                loop {
                    key.clear();
                    key.push_str(str);
                    key.push_str("##");
                    key.push_str(&idx.to_string());

                    if !quick_idx_map.contains_key(&key) {
                        quick_idx_map.insert(key, i);
                        break;
                    }

                    idx += 1;
                }
            } else {
                quick_idx_map.insert(str.clone(), i);
            }
        }

        quick_idx_map
    }

    fn map_fingerprinting_cases(
        &self,
        string_values: &Vec<String>,
        values: &[VMEntryValue],
        quick_map_idx: &FxHashMap<String, usize>,
    ) -> Option<Result<FingerprintEntry, anyhow::Error>> {
        let string_set: HashSet<&str> = string_values.iter().map(|k| k.as_str()).collect();

        SIGNAL_PATTERNS
            .iter()
            .find(|pattern| (pattern.matcher)(&string_set))
            .map(|pattern| (pattern.entry_builder)(quick_map_idx, string_values, values))
    }

    fn grab_keys_order(
        &self,
        cfg: &ControlFlowGraph,
    ) -> Result<(VecDeque<String>, FxHashMap<String, Vec<Instruction>>), anyhow::Error> {
        let cfa = ControlFlowAnalysis::new(cfg);
        let structures = cfa.quick_conditionals_analysis();

        let mut mapped_constants = FxHashMap::default();
        let mut keys: FxHashSet<String> = FxHashSet::default();
        let collected_registers = self.get_static_registers(cfg.blocks.get(&self.function_start).unwrap());
        let mut found_ret_case = false;

        for (_, structure) in structures.structures {
            if let FlowStructure::IfElseThen(structure) = structure {
                if structure.else_block.is_none() {
                    continue;
                }

                let value = self.find_string_cmp_register(
                    cfg,
                    structure.condition_block,
                    structure.cond as u16,
                );
                
                if let Some(value) = value {
                    if !found_ret_case {
                        // avoids final CFF case
                        let else_bb = cfg.blocks.get(&structure.else_block.unwrap()).unwrap();
                        if else_bb.successors.is_empty() {
                            found_ret_case = true;
                            continue;
                        }
                    }

                    keys.insert(value.clone());
                    mapped_constants.insert(value, structure.clone());
                }
            }
        }

        let mut keys_order = VecDeque::new();
        let mut current_key = "__undefined".to_string();

        let mut visited_funcs = FxHashSet::default();
        visited_funcs.insert(self.function_start);

        let mut key_to_instructions: FxHashMap<String, Vec<Instruction>> = FxHashMap::default();
        
        loop {
            keys_order.push_back(current_key.clone());

            let structure = mapped_constants.remove(current_key.as_str()).context(format!("expected mapped constant: {}", current_key.as_str()))?;
            let collected_instructions = self.collect_instructions(
                cfg,
                structure.else_block.unwrap(),
                structure.merge_block,
            );
            let instructions: Vec<&Instruction> = collected_instructions.iter().collect();

            let res = self.find_next_key(
                &instructions,
                &collected_registers,
                &keys,
                current_key.as_str(),
                &mut visited_funcs,
            );
            
            key_to_instructions.insert(current_key.clone(), collected_instructions);

            if let Some(s) = res {
                keys.remove(&current_key);
                current_key = s.clone();
            } else {
                break;
            }
        }

        Ok((keys_order, key_to_instructions))
    }

    fn collect_instructions(
        &self,
        cfg: &ControlFlowGraph,
        start: NodeId,
        target: NodeId,
    ) -> Vec<Instruction> {
        let mut instructions = Vec::new();

        let mut vec = VecDeque::new();
        let mut visited = FxHashSet::default();
        vec.push_front(start);

        while let Some(current_block) = vec.pop_front() {
            if visited.contains(&current_block) {
                continue;
            }
            visited.insert(current_block);
            if current_block == target {
                break;
            }

            let bb = cfg.blocks.get(&current_block).unwrap();
            instructions.extend(bb.instructions.clone());

            for successor in &bb.successors {
                vec.push_back(successor.target_id);
            }
        }

        instructions
    }

    fn find_next_key(
        &self,
        instructions: &Vec<&Instruction>,
        collected_registers: &FxHashMap<u16, String>,
        keys: &FxHashSet<String>,
        current_key: &str,
        visited_funcs: &mut FxHashSet<NodeId>,
    ) -> Option<String> {
        for instruction in instructions {
            if let Instruction::RegisterVMFunc(func) = instruction {
                if visited_funcs.contains(&func.jump.pos) {
                    continue;
                }

                visited_funcs.insert(func.jump.pos);
                let body: &Vec<&Instruction> = &self
                    .functions
                    .get(&func.jump.pos)
                    .unwrap()
                    .body
                    .iter()
                    .map(|(_, k)| k)
                    .collect();

                if let Some(k) = self.find_next_key(body, collected_registers, keys, current_key, visited_funcs) {
                    return Some(k);
                }
            }
            
            let s = match instruction {
                Instruction::NewLiteral(lit) => {
                    if let LiteralInstructionType::String(s) = &lit.data {
                        // println!("found string: {}", s);
                        s
                    } else {
                        continue;
                    }
                }
                Instruction::SetProperty(prop) if collected_registers.contains_key(&prop.val_reg) => {
                    // println!("found collected string: {}", collected_registers.get(&prop.val_reg).unwrap());
                    collected_registers.get(&prop.val_reg).unwrap()
                },
                _ => continue,
            };
            
            if s != current_key && keys.contains(s) {
                return Some(s.clone());
            }
        }

        None
    }

    fn collect_strings_and_values(
        &self,
        function_id: NodeId,
        visited_functions: &mut FxHashSet<NodeId>,
    ) -> (Vec<String>, Vec<VMEntryValue>) {
        let mut strings = Vec::new();
        let mut values = Vec::new();
        let function = self.functions.get(&function_id).unwrap();

        for (_, instruction) in &function.body {
            if let Instruction::NewLiteral(literal) = instruction {
                match &literal.data {
                    LiteralInstructionType::String(s) => {
                        strings.push(s.clone());
                        values.push(VMEntryValue::String(s));
                    }
                    LiteralInstructionType::Byte(b) => {
                        values.push(VMEntryValue::Integer(*b as isize));
                    }
                    LiteralInstructionType::Integer(i) => {
                        values.push(VMEntryValue::Integer(*i as isize));
                    }
                    _ => {}
                }
            }

            if let Instruction::RegisterVMFunc(op) = instruction
                && !visited_functions.contains(&op.jump.pos)
            {
                visited_functions.insert(op.jump.pos);

                let (ss, vv) = self.collect_strings_and_values(op.jump.pos, visited_functions);
                strings.extend(ss);
                values.extend(vv);
            }
        }

        (strings, values)
    }

    fn find_string_cmp_register(
        &self,
        cfg: &ControlFlowGraph,
        cond_block: NodeId,
        cond_reg: u16,
    ) -> Option<String> {
        let condition_block = cfg.blocks.get(&cond_block)?;
        let mut strings_or_undefined_registers = FxHashMap::default();

        for instruction in &condition_block.instructions {
            if let Instruction::NewLiteral(literal) = instruction {
                match &literal.data {
                    LiteralInstructionType::Undefined => {
                        strings_or_undefined_registers
                            .insert(literal.ret_reg, "__undefined".to_string());
                    }
                    LiteralInstructionType::String(s) => {
                        strings_or_undefined_registers.insert(literal.ret_reg, s.to_string());
                    }
                    _ => {}
                }
            }

            if let Instruction::Binary(bin) = instruction {
                if cond_reg != bin.ret_reg || !matches!(bin.op, BinaryOperator::Equals) {
                    continue;
                }

                if strings_or_undefined_registers.contains_key(&bin.a) {
                    return Some(
                        strings_or_undefined_registers
                            .get(&bin.a)
                            .unwrap()
                            .to_string(),
                    );
                } else if strings_or_undefined_registers.contains_key(&bin.b) {
                    return Some(
                        strings_or_undefined_registers
                            .get(&bin.b)
                            .unwrap()
                            .to_string(),
                    );
                }
            }
        }

        None
    }
}

type PatternMatcher = fn(&HashSet<&str>) -> bool;
type EntryBuilderFn = fn(
    &FxHashMap<String, usize>,
    &Vec<String>,
    &[VMEntryValue],
) -> Result<FingerprintEntry, anyhow::Error>;

struct SignalPattern {
    matcher: PatternMatcher,
    entry_builder: EntryBuilderFn,
}

static SIGNAL_PATTERNS: Lazy<Vec<SignalPattern>> = Lazy::new(|| {
    vec![
        SignalPattern {
            matcher: |set| set.contains("d.") && set.contains("so.") && set.contains("s."),
            entry_builder: |m, s, v| {
                BrowserKeysEntry::parse(m, s, v).map(FingerprintEntry::BrowserKeys)
            },
        },
        SignalPattern {
            matcher: |set| {
                set.iter()
                    .any(|k| k.contains(":navigator.hardwareConcurrency"))
            },
            entry_builder: |m, s, v| {
                BrowserDataEntry::parse(m, s, v).map(FingerprintEntry::BrowserData)
            },
        },
        SignalPattern {
            matcher: |set| {
                set.contains("userAgentData") && set.contains("CLIENT_HINTS_DATA_UNDEFINED_OR_NULL")
            },
            entry_builder: |m, s, v| {
                UserAgentDataEntry::parse(m, s, v).map(FingerprintEntry::UserAgentData)
            },
        },
        SignalPattern {
            matcher: |set| set.contains("matchMedia"),
            entry_builder: |m, s, v| {
                UserPreferencesAndBatteryEntry::parse(m, s, v)
                    .map(FingerprintEntry::UserPreferencesAndBattery)
            },
        },
        SignalPattern {
            matcher: |set| set.contains("__proto__") && set.contains("PluginArray"),
            entry_builder: |m, s, v| {
                TamperingAndPluginsEntry::parse(m, s, v).map(FingerprintEntry::TamperingAndPlugins)
            },
        },
        SignalPattern {
            matcher: |set| set.contains("createOscillator"),
            entry_builder: |m, s, v| AudioEntry::parse(m, s, v).map(FingerprintEntry::Audio),
        },
        SignalPattern {
            matcher: |set| {
                set.contains("UNMASKED_VENDOR_WEBGL") && set.contains("UNMASKED_RENDERER_WEBGL")
            },
            entry_builder: |m, s, v| WebGLEntry::parse(m, s, v).map(FingerprintEntry::WebGL),
        },
        SignalPattern {
            matcher: |set| set.contains("<iframe height=0 width=0></iframe>"),
            entry_builder: |m, s, v| {
                DivRenderTimeEntry::parse(m, s, v).map(FingerprintEntry::DivRenderTime)
            },
        },
        SignalPattern {
            matcher: |set| set.contains("<html><head></head><body></body></html>"),
            entry_builder: |m, s, v| {
                ComputedStyleEntry::parse(m, s, v).map(FingerprintEntry::ComputedStyle)
            },
        },
        SignalPattern {
            matcher: |set| {
                set.contains("getBoundingClientRect")
                    && set.contains("srcdoc")
                    && set.contains("iframe")
                    && set.contains("toJSON")
            },
            entry_builder: |m, s, v| {
                HTMLRenderEntry::parse(m, s, v).map(FingerprintEntry::HTMLRender)
            },
        },
        SignalPattern {
            matcher: |set| {
                set.contains("/h/")
                    && set.contains("/cdn-cgi/challenge-platform")
                    && set.contains("img")
            },
            entry_builder: |m, s, v| ImageEntry::parse(m, s, v).map(FingerprintEntry::Image),
        },
        SignalPattern {
            matcher: |set| set.contains("links") && set.contains("forms"),
            entry_builder: |m, s, v| {
                DocumentObjectChecksEntry::parse(m, s, v)
                    .map(FingerprintEntry::DocumentObjectChecks)
            },
        },
        SignalPattern {
            matcher: |set| set.contains("styleSheets"),
            entry_builder: |m, s, v| CssEntry::parse(m, s, v).map(FingerprintEntry::CSS),
        },
        SignalPattern {
            matcher: |set| {
                set.contains("insertRule") || set.contains("appendData")
                // || set.contains("insertAdjacentHTML")
            },
            entry_builder: |m, s, v| {
                ElementParentChecksEntry::parse(m, s, v).map(FingerprintEntry::ElementParentChecks)
            },
        },
        SignalPattern {
            matcher: |set| {
                set.contains("pfp")
                    && set.contains("sL")
                    && set.contains("ssL")
                    && set.contains("tL")
            },
            entry_builder: |m, s, v| DocumentEntry::parse(m, s, v).map(FingerprintEntry::Document),
        },
        SignalPattern {
            matcher: |set| set.contains("px sans-serif"),
            entry_builder: |m, s, v| {
                EmojiOsCheckEntry::parse(m, s, v).map(FingerprintEntry::EmojiOsCheck)
            },
        },
        SignalPattern {
            matcher: |set| set.contains("getTimezoneOffset") && set.contains("DateTimeFormat"),
            entry_builder: |m, s, v| TimezoneEntry::parse(m, s, v).map(FingerprintEntry::Timezone),
        },
        SignalPattern {
            matcher: |set| set.contains("eo-UA") && set.contains("DateTimeFormat"),
            entry_builder: |m, s, v| LanguageEntry::parse(m, s, v).map(FingerprintEntry::Language),
        },
        SignalPattern {
            matcher: |set| set.contains("encodedBodySize"),
            entry_builder: |m, s, v| {
                PerformanceEntriesEntry::parse(m, s, v).map(FingerprintEntry::Performance)
            },
        },
        SignalPattern {
            matcher: |set| {
                set.contains("performance")
                    && set.contains("memory")
                    && set.contains("https://example.org/")
            },
            entry_builder: |m, s, v| {
                PerformanceMemoryEntry::parse(m, s, v).map(FingerprintEntry::PerformanceMemory)
            },
        },
        SignalPattern {
            matcher: |set| {
                set.contains("postMessage")
                    && set.contains("terminate")
                    && set.contains("data")
                    && set.contains("onmessage")
                    && set.iter().any(|k| k.contains("performance.now();"))
            },
            entry_builder: |m, s, v| {
                WorkerPerformanceTimingEntry::parse(m, s, v)
                    .map(FingerprintEntry::WorkerPerformanceTiming)
            },
        },
        SignalPattern {
            matcher: |set| {
                set.contains("the force is not strong with this one")
                    && set.contains("tangentialPressure")
            },
            entry_builder: |m, s, v| POWClickEntry::parse(m, s, v).map(FingerprintEntry::POWClick),
        },
        SignalPattern {
            matcher: |set| set.contains("the force is not strong with this one"),
            entry_builder: |m, s, v| POWEntry::parse(m, s, v).map(FingerprintEntry::POW),
        },
        SignalPattern {
            matcher: |set| set.contains("Request for the Private Access Token challenge."),
            entry_builder: |m, s, v| {
                PrivateAccessTokenEntry::parse(m, s, v).map(FingerprintEntry::PrivateAccessToken)
            },
        },
        SignalPattern {
            matcher: |set| set.contains("COMMENT_NODE"),
            entry_builder: |m, s, v| {
                SeleniumEntry::parse(m, s, v).map(FingerprintEntry::SeleniumUnknown)
            },
        },
        SignalPattern {
            matcher: |set| {
                set.contains("CanvasRenderingContext2D") && set.contains("CanvasGradient")
            },
            entry_builder: |m, s, v| {
                WebGLNativeFunctionChecksEntry::parse(m, s, v)
                    .map(FingerprintEntry::WebGLNativeFunctionChecks)
            },
        },
        SignalPattern {
            matcher: |set| set.contains("SQRT1_2"),
            entry_builder: |m, s, v| MathEntry::parse(m, s, v).map(FingerprintEntry::Math),
        },
        SignalPattern {
            matcher: |set| set.contains("structuredClone"),
            entry_builder: |m, s, v| {
                EngineBehaviorEntry::parse(m, s, v).map(FingerprintEntry::EngineBehavior)
            },
        },
        SignalPattern {
            matcher: |set| {
                set.contains("eval")
                    && set.contains("length")
                    && set.iter().any(|k| k.contains("throw Error"))
            },
            entry_builder: |m, s, v| {
                EvalErrorEntry::parse(m, s, v).map(FingerprintEntry::EvalError)
            },
        },
        SignalPattern {
            matcher: |set| set.contains("scale(1.000998)") && set.contains("-10000px"),
            entry_builder: |m, s, v| {
                UnknownHashesEntry::parse(m, s, v).map(FingerprintEntry::UnknownHashes)
            },
        },
        SignalPattern {
            matcher: |set| {
                set.contains("replace")
                    && set.contains(" ")
                    && set.contains("")
                    && set.contains("toFixed")
                    && set.contains("message")
            },
            entry_builder: |m, s, v| StackEntry::parse(m, s, v).map(FingerprintEntry::Stack),
        },
        SignalPattern {
            matcher: |set| {
                // let's do this for the moment
                set.len() < 20
                    && set.contains("eval")
                    && set.contains("this")
                    && set.contains("length")
                    && set.contains("chl-exc")
            },
            entry_builder: |m, s, v| {
                StaticValueEntry::parse(m, s, v).map(FingerprintEntry::StaticValue)
            },
        },
    ]
});
