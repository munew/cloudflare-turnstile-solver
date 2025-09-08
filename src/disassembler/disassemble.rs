use crate::disassembler::RecursiveDisassembler;
use crate::parser::{
    functions::FindFunctions, magic_bits::OpcodeParser, offset::FindOffset,
    payload::PayloadKeyExtractor, vm::ScriptVisitor,
};
use anyhow::Context;
use oxc_allocator::Allocator;
use oxc_ast::ast::Program;
use oxc_ast_visit::{Visit, VisitMut};
use rustc_hash::FxHashMap;

pub fn parse_script_interpreter<'a>(
    program: &'a mut Program<'a>,
    allocator: &'a Allocator,
) -> Result<(
    RecursiveDisassembler<'a>,
    ScriptVisitor,
    PayloadKeyExtractor,
    String,
    String,
    FxHashMap<String, String>,
), anyhow::Error> {
    let mut find_functions = FindFunctions::default();
    find_functions.visit_program(program);

    let mut find_offset = FindOffset::new(&allocator);
    find_offset.visit_program(program);

    let mut opcode_parser =
        OpcodeParser::new(find_functions.constants, find_functions.functions.clone());
    opcode_parser.visit_program(program);

    let mut opcode_to_function_name = FxHashMap::default();
    for (function_name, op) in &find_functions.functions {
        if opcode_parser.opcodes.get(op).is_none() {
            continue;
        }
        opcode_to_function_name.insert(
            opcode_parser.opcodes.get(op).cloned().unwrap().to_string(),
            function_name.to_string(),
        );
    }

    let mut payload_key_extractor = PayloadKeyExtractor::default();
    payload_key_extractor.visit_program(program);

    let mut vm_bytecode_visitor = ScriptVisitor::default();
    vm_bytecode_visitor.visit_program(program);
    if vm_bytecode_visitor.initial_vm.is_none() {
        panic!("vm code was not found");
    }

    Ok((
        RecursiveDisassembler::new(
            opcode_parser.opcodes.clone(),
            find_offset.key_expr.expect("Key expression not found"),
            find_functions.key,
            find_offset.offset as u16,
            vm_bytecode_visitor.initial_vm.as_ref().context("could not find initial vm")?.as_str(),
        )?,
        vm_bytecode_visitor,
        payload_key_extractor,
        opcode_parser.create_function_ident.to_string(),
        find_functions.function_with_opcodes.to_string(),
        opcode_to_function_name,
    ))
}
