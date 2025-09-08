use crate::parser::magic_bits::{HeapType, LiteralType, Opcode};
use crate::parser::utils::eval_key_expr;
use anyhow::{bail, Context, Error};
use base64::Engine;
use oxc_ast::ast::Expression;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::BTreeMap;
use crate::disassembler::instructions::{ArrayPushInstruction, BinaryInstruction, BindOpcodeInstruction, CallInstruction, ConditionalJumpInstruction, GetPropertyInstruction, HeapInstruction, HeapSubInstruction, Instruction, JumpInstruction, LiteralInstructionType, MoveInstruction, NewInstruction, NewLiteralInstruction, PopInstruction, RegisterSwapInstruction, RegisterVMFunctionInstruction, RegisteredFunction, ReturnInstruction, SetPropertyInstruction, SplicePopInstruction, ThrowInstruction, UnaryInstruction, Value};

pub mod disassemble;
pub mod instructions;

unsafe impl<'a> Send for RecursiveDisassembler<'a> {}
unsafe impl<'a> Sync for RecursiveDisassembler<'a> {}

pub struct RecursiveDisassembler<'a> {
    opcodes: FxHashMap<u16, Opcode>,
    key_expressions: Expression<'a>,
    offset: u16,
    initial_vm_found_key: u16,
}

impl<'a> RecursiveDisassembler<'a> {
    pub fn new(
        opcodes: FxHashMap<u16, Opcode>,
        key_expressions: Expression<'a>,
        first_key: u16,
        offset: u16,
        encoded_init_vm: &str,
    ) -> Result<Self, Error> {
        let init_vm = base64::prelude::BASE64_STANDARD.decode(encoded_init_vm)?;

        let mut s = Self {
            opcodes,
            offset,
            key_expressions,
            initial_vm_found_key: u16::MAX,
        };

        let (base_instructions, _) = s.read_vm(&init_vm, 0, first_key)?;
        for (_, instruction) in base_instructions.iter().rev() {
            if let Instruction::NewLiteral(lit) = instruction
                && let LiteralInstructionType::Byte(b) = &lit.data
            {
                s.initial_vm_found_key = *b;
                break;
            }
        }

        if s.initial_vm_found_key == u16::MAX {
            bail!("failed to find initial vm key");
        }
        Ok(s)
    }

    pub fn read_encoded_vm(
        &mut self,
        encoded_vm: &str,
    ) -> Result<
        (
            Vec<(usize, Instruction)>,
            FxHashMap<usize, RegisteredFunction>,
        ),
        Error,
    > {
        let vm = base64::prelude::BASE64_STANDARD.decode(encoded_vm)?;
        self.read_vm(&vm, 0, self.initial_vm_found_key)
    }

    fn read_vm(
        &mut self,
        bytecode: &[u8],
        start: usize,
        start_key: u16,
    ) -> Result<
        (
            Vec<(usize, Instruction)>,
            FxHashMap<usize, RegisteredFunction>,
        ),
        Error,
    > {
        let mut visited = FxHashSet::<usize>::default();
        let mut collected_function_jumps = Vec::<FunctionJump>::new();
        let mut functions = FxHashMap::<usize, RegisteredFunction>::default();

        collected_function_jumps.push((start, start_key));

        while let Some(jump) = collected_function_jumps.pop() {
            if visited.contains(&jump.0) {
                continue;
            }

            visited.insert(jump.0);

            let (instructions, values, end) = self.read(
                bytecode,
                jump.0,
                jump.1,
                &mut visited,
                &mut collected_function_jumps,
            )?;
            let body = instructions.into_iter().collect::<Vec<_>>();

            let registered_function = RegisteredFunction {
                start: jump.0 as u64,
                end: end as u64,
                body,
                values,
            };

            functions.insert(jump.0, registered_function);
        }

        let main = functions.remove(&0).unwrap();

        Ok((main.body, functions))
    }

    fn read(
        &mut self,
        bytecode: &[u8],
        start: usize,
        start_key: u16,
        visited: &mut FxHashSet<usize>,
        collected_functions: &mut Vec<FunctionJump>,
    ) -> Result<(BTreeMap<usize, Instruction>, Vec<Value>, usize), Error> {
        let mut index = start;
        let mut key = start_key;
        let mut map = BTreeMap::default();
        let mut values = Vec::<Value>::new();

        let mut instruction_index;
        loop {
            instruction_index = index;
            if index == bytecode.len() {
                break;
            }

            let op = (key ^ (self.offset + bytecode[index] as u16)) & 0xFF;
            let result = eval_key_expr(&self.key_expressions, key as i64, op as i64)
                .context("failed to evaluate key expression")?;
            key = (result & 0xFF) as u16;
            index += 1;

            let instruction = self.read_opcode(bytecode, op, &mut index, &mut key)?;
            if matches!(instruction, Instruction::SplicePop(_))
                || matches!(instruction, Instruction::Throw(_))
            {
                if let Instruction::SplicePop(sp) = instruction {
                    map.insert(
                        instruction_index,
                        Instruction::Return(ReturnInstruction {
                            return_register: sp.reg,
                        }),
                    );
                } else {
                    map.insert(instruction_index, instruction);
                }

                break;
            }

            match &instruction {
                Instruction::RegisterVMFunc(func) => {
                    if !visited.contains(&func.jump.pos) {
                        collected_functions.push((func.jump.pos, func.jump.new_key));
                    }
                }
                Instruction::Jump(jmp) => {
                    if visited.contains(&jmp.pos) {
                        map.insert(instruction_index, instruction);
                        break;
                    }

                    index = jmp.pos;
                    key = jmp.new_key;
                    visited.insert(jmp.pos);
                }
                Instruction::ConditionalJump(jmp) => {
                    if visited.contains(&jmp.jump.pos) || visited.contains(&index) {
                        map.insert(instruction_index, instruction);
                        break;
                    }

                    let (res, v, _) = self.read(
                        bytecode,
                        jmp.jump.pos,
                        jmp.jump.new_key,
                        visited,
                        collected_functions,
                    )?;
                    map.extend(res);
                    values.extend(v);

                    visited.insert(jmp.jump.pos);
                }
                Instruction::NewLiteral(lit) => match &lit.data {
                    LiteralInstructionType::String(s) => values.push(Value::String(s.clone())),
                    LiteralInstructionType::Undefined => values.push(Value::Undefined),
                    LiteralInstructionType::CopyState(jmp) => {
                        if visited.contains(&jmp.pos) {
                            map.insert(instruction_index, instruction);
                            break;
                        }

                        let (res, v, _) = self.read(
                            bytecode,
                            jmp.pos,
                            jmp.new_key,
                            visited,
                            collected_functions,
                        )?;
                        map.extend(res);
                        values.extend(v);

                        visited.insert(jmp.pos);
                    }
                    _ => {}
                },
                _ => {}
            }

            map.insert(instruction_index, instruction);
        }

        Ok((map, values, instruction_index))
    }

    fn read_opcode(
        &mut self,
        bytecode: &[u8],
        opcode: u16,
        idx: &mut usize,
        key: &mut u16,
    ) -> Result<Instruction, Error> {
        if let Some(opcode) = self.opcodes.get(&opcode) {
            match opcode {
                Opcode::Bind(op) => {
                    let reg = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));
                    let opcode = self.read_byte(bytecode, idx, *key, None);
                    let arg = self.read_byte(bytecode, idx, *key, Some(op.bits[1]));

                    let has_register = self.opcodes.contains_key(&(reg));

                    if let Some(handler_func) = self.opcodes.get(&(opcode))
                        && !has_register
                    {
                        self.opcodes.insert(reg, handler_func.clone());
                    }

                    Ok(Instruction::BindOpcode(BindOpcodeInstruction {
                        reg,
                        opcode,
                        arg,
                    }))
                }
                Opcode::RegisterVMFunction(op) => {
                    let dst = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));

                    let first_byte = self.read_byte(bytecode, idx, *key, None) as i32;
                    let second_byte = self.read_byte(bytecode, idx, *key, None) as i32;
                    let third_byte = self.read_byte(bytecode, idx, *key, None) as i32;
                    let pos = (first_byte << 16) | (second_byte << 8) | third_byte;
                    let new_key = self.read_byte(bytecode, idx, *key, Some(op.bits[1]));

                    Ok(Instruction::RegisterVMFunc(RegisterVMFunctionInstruction {
                        jump: JumpInstruction {
                            pos: pos as usize,
                            new_key,
                        },
                        ret_reg: dst,
                    }))
                }
                Opcode::NewObject(op) => {
                    let reg = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));

                    Ok(Instruction::NewObject(NewInstruction { ret_reg: reg }))
                }
                Opcode::NewArray(op) => {
                    let reg = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));
                    Ok(Instruction::NewArray(NewInstruction { ret_reg: reg }))
                }
                Opcode::Throw(op) => {
                    let reg = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));
                    Ok(Instruction::Throw(ThrowInstruction { exception_reg: reg }))
                }
                Opcode::Jump(op) => {
                    let first_byte = self.read_byte(bytecode, idx, *key, None);
                    let second_byte = self.read_byte(bytecode, idx, *key, None);
                    let third_byte = self.read_byte(bytecode, idx, *key, None);

                    let jump = ((first_byte as i32) << 16)
                        | ((second_byte as i32) << 8)
                        | (third_byte as i32);

                    let new_key = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));

                    Ok(Instruction::Jump(JumpInstruction {
                        pos: jump as usize,
                        new_key,
                    }))
                }
                Opcode::Move(op) => {
                    let dst = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));
                    let src = self.read_byte(bytecode, idx, *key, Some(op.bits[1]));

                    Ok(Instruction::Move(MoveInstruction {
                        src_reg: src,
                        dst_reg: dst,
                    }))
                }
                Opcode::SplicePop(op) => {
                    let register = self.read_byte(bytecode, idx, *key, Some(op.bits[1]));

                    Ok(Instruction::SplicePop(SplicePopInstruction {
                        arrays: vec![op.bits[0], op.bits[2]],
                        reg: register,
                    }))
                }
                Opcode::NewLiteral(op) => {
                    let reg = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));
                    let datatype_int = self.read_byte(bytecode, idx, *key, Some(op.bits[1]));

                    if let Some(datatype) = op.tests.get(&(datatype_int)) {
                        match datatype.type_ {
                            LiteralType::Float => {
                                let f = self.decode_float(bytecode, idx, *key);
                                Ok(Instruction::NewLiteral(NewLiteralInstruction {
                                    data: LiteralInstructionType::Float(f),
                                    ret_reg: reg,
                                }))
                            }
                            LiteralType::CopyState => {
                                let first_byte = self.read_byte(bytecode, idx, *key, None) as i32;
                                let second_byte = self.read_byte(bytecode, idx, *key, None) as i32;
                                let third_byte = self.read_byte(bytecode, idx, *key, None) as i32;

                                let jmp = (first_byte << 16) | (second_byte << 8) | third_byte;
                                let new_key =
                                    self.read_byte(bytecode, idx, *key, Some(datatype.bits[0]));

                                Ok(Instruction::NewLiteral(NewLiteralInstruction {
                                    data: LiteralInstructionType::CopyState(JumpInstruction {
                                        pos: jmp as usize,
                                        new_key,
                                    }),
                                    ret_reg: reg,
                                }))
                            }
                            LiteralType::NextValue => {
                                let value = self.read_varint(bytecode, idx, *key)?;

                                Ok(Instruction::NewLiteral(NewLiteralInstruction {
                                    data: LiteralInstructionType::Integer(value as i64),
                                    ret_reg: reg,
                                }))
                            }
                            LiteralType::Integer => {
                                let byte =
                                    self.read_byte(bytecode, idx, *key, Some(datatype.bits[0]));

                                Ok(Instruction::NewLiteral(NewLiteralInstruction {
                                    data: LiteralInstructionType::Byte(byte),
                                    ret_reg: reg,
                                }))
                            }
                            LiteralType::NaN => {
                                Ok(Instruction::NewLiteral(NewLiteralInstruction {
                                    data: LiteralInstructionType::NaN,
                                    ret_reg: reg,
                                }))
                            }
                            LiteralType::True => {
                                Ok(Instruction::NewLiteral(NewLiteralInstruction {
                                    data: LiteralInstructionType::True,
                                    ret_reg: reg,
                                }))
                            }
                            LiteralType::False => {
                                Ok(Instruction::NewLiteral(NewLiteralInstruction {
                                    data: LiteralInstructionType::False,
                                    ret_reg: reg,
                                }))
                            }
                            LiteralType::Null => {
                                Ok(Instruction::NewLiteral(NewLiteralInstruction {
                                    data: LiteralInstructionType::Null,
                                    ret_reg: reg,
                                }))
                            }
                            LiteralType::Infinity => {
                                Ok(Instruction::NewLiteral(NewLiteralInstruction {
                                    data: LiteralInstructionType::Infinity,
                                    ret_reg: reg,
                                }))
                            }
                            LiteralType::String => {
                                let len = self.read_varint(bytecode, idx, *key)?;

                                let mut str = String::new();
                                for _ in 0..len {
                                    let byte =
                                        self.read_byte(bytecode, idx, *key, Some(datatype.bits[0]));
                                    str.push(byte as u8 as char);
                                }

                                Ok(Instruction::NewLiteral(NewLiteralInstruction {
                                    data: LiteralInstructionType::String(str),
                                    ret_reg: reg,
                                }))
                            }
                            LiteralType::Regexp => {
                                let len = self.read_varint(bytecode, idx, *key)?;
                                let mut pattern = String::new();

                                for _ in 0..len {
                                    let byte =
                                        self.read_byte(bytecode, idx, *key, Some(datatype.bits[0]));
                                    pattern.push(byte as u8 as char);
                                }

                                let flags_len =
                                    self.read_byte(bytecode, idx, *key, Some(datatype.bits[1]));
                                let mut flags = String::new();

                                for _ in 0..flags_len {
                                    let byte =
                                        self.read_byte(bytecode, idx, *key, Some(datatype.bits[2]));
                                    flags.push(byte as u8 as char);
                                }

                                Ok(Instruction::NewLiteral(NewLiteralInstruction {
                                    data: LiteralInstructionType::Regexp((pattern, flags)),
                                    ret_reg: reg,
                                }))
                            }
                            _ => Err(Error::msg("unknown literal type")),
                        }
                    } else {
                        Ok(Instruction::NewLiteral(NewLiteralInstruction {
                            data: LiteralInstructionType::Undefined,
                            ret_reg: reg,
                        }))
                    }
                }
                Opcode::JumpIf(op) => {
                    let test_reg = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));
                    let first_byte = self.read_byte(bytecode, idx, *key, None);
                    let second_byte = self.read_byte(bytecode, idx, *key, None);
                    let third_byte = self.read_byte(bytecode, idx, *key, None);
                    let jump = ((first_byte as i32) << 16)
                        | ((second_byte as i32) << 8)
                        | (third_byte as i32);
                    let new_key = self.read_byte(bytecode, idx, *key, Some(op.bits[1]));

                    Ok(Instruction::ConditionalJump(ConditionalJumpInstruction {
                        jump: JumpInstruction {
                            pos: jump as usize,
                            new_key,
                        },
                        test_reg,
                    }))
                }
                Opcode::GetProperty(op) => {
                    let res = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));
                    let obj = self.read_byte(bytecode, idx, *key, Some(op.bits[1]));
                    let key = self.read_byte(bytecode, idx, *key, Some(op.bits[2]));

                    Ok(Instruction::GetProperty(GetPropertyInstruction {
                        obj_reg: obj,
                        key_reg: key,
                        ret_reg: res,
                    }))
                }
                Opcode::CallFuncNoContext(op) => {
                    let result_reg = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));
                    let func_reg = self.read_byte(bytecode, idx, *key, Some(op.bits[1]));
                    let args_len = self.read_byte(bytecode, idx, *key, Some(op.bits[2]));

                    let mut args = Vec::<u16>::new();
                    for _ in 0..args_len {
                        let reg = self.read_byte(bytecode, idx, *key, Some(op.bits[3]));
                        args.push(reg);
                    }

                    Ok(Instruction::Call(CallInstruction {
                        object_arg: None,
                        func_reg,
                        reg_args: args,
                        ret_reg: result_reg,
                    }))
                }
                Opcode::SetProperty(op) => {
                    let obj = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));
                    let key_ = self.read_byte(bytecode, idx, *key, Some(op.bits[1]));
                    let res = self.read_byte(bytecode, idx, *key, Some(op.bits[2]));

                    Ok(Instruction::SetProperty(SetPropertyInstruction {
                        obj_reg: obj,
                        key_reg: key_,
                        val_reg: res,
                    }))
                }

                Opcode::SwapRegister(op) => {
                    let first = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));
                    let second = self.read_byte(bytecode, idx, *key, Some(op.bits[1]));

                    let first_opcode = self.opcodes.contains_key(&(first));
                    let second_opcode = self.opcodes.contains_key(&(second));
                    if first_opcode || second_opcode {
                        if first_opcode && second_opcode {
                            let first_op = self.opcodes.remove(&(first)).unwrap();
                            let second_op = self.opcodes.remove(&(second)).unwrap();

                            self.opcodes.insert(first, second_op);
                            self.opcodes.insert(second, first_op);

                            // println!("swapped opcodes between R{} and R{}", first, second);
                        } else if first_opcode {
                            let op_clone = self.opcodes.remove(&(first)).unwrap();
                            self.opcodes.remove(&(first));
                            self.opcodes.insert(second, op_clone);

                            // println!("moved opcode from R{} to R{}", first, second);
                        } else {
                            let op_clone = self.opcodes.remove(&(second)).unwrap();
                            self.opcodes.remove(&(second));
                            self.opcodes.insert(first, op_clone);

                            // println!("moved opcode from R{} to R{}", second, first);
                        }
                    }

                    Ok(Instruction::Swap(RegisterSwapInstruction { first, second }))
                }
                Opcode::ArrayPush(op) => {
                    let arr = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));
                    let obj = self.read_byte(bytecode, idx, *key, Some(op.bits[1]));

                    Ok(Instruction::Push(ArrayPushInstruction {
                        arr_reg: arr,
                        val_reg: obj,
                    }))
                }
                Opcode::Binary(op) => {
                    let dst = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));

                    let (a, b) = if !op.swap {
                        (
                            self.read_byte(bytecode, idx, *key, Some(op.bits[1])),
                            self.read_byte(bytecode, idx, *key, Some(op.bits[2])),
                        )
                    } else {
                        (
                            self.read_byte(bytecode, idx, *key, Some(op.bits[2])),
                            self.read_byte(bytecode, idx, *key, Some(op.bits[1])),
                        )
                    };

                    Ok(Instruction::Binary(BinaryInstruction {
                        op: op.operator.clone(),
                        ret_reg: dst,
                        a,
                        b,
                    }))
                }
                Opcode::Unary(op) => {
                    let res = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));
                    let a = self.read_byte(bytecode, idx, *key, Some(op.bits[1]));

                    Ok(Instruction::Unary(UnaryInstruction {
                        op: op.operator.clone(),
                        a,
                        ret_reg: res,
                    }))
                }
                Opcode::Pop(op) => {
                    let arr = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));
                    let reg = self.read_byte(bytecode, idx, *key, Some(op.bits[1]));

                    Ok(Instruction::Pop(PopInstruction {
                        arr_reg: arr,
                        ret_reg: reg,
                    }))
                }
                Opcode::Heap(op) => {
                    let test = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));
                    let type_ = op.closures.get(&test).unwrap();

                    let int = self.read_varint(bytecode, idx, *key)?;
                    match type_.closure_type {
                        HeapType::Init => {
                            let mut vec = Vec::<usize>::new();
                            for _ in 0..int {
                                vec.push(self.read_varint(bytecode, idx, *key)?);
                            }

                            Ok(Instruction::Heap(HeapInstruction {
                                sub_instruction: HeapSubInstruction::Init(vec),
                            }))
                        }
                        HeapType::Get => {
                            let target_reg =
                                self.read_byte(bytecode, idx, *key, Some(type_.bits[0]));
                            Ok(Instruction::Heap(HeapInstruction {
                                sub_instruction: HeapSubInstruction::Get(MoveInstruction {
                                    src_reg: int as u16,
                                    dst_reg: target_reg,
                                }),
                            }))
                        }
                        HeapType::Set => {
                            let target_reg =
                                self.read_byte(bytecode, idx, *key, Some(type_.bits[0]));
                            Ok(Instruction::Heap(HeapInstruction {
                                sub_instruction: HeapSubInstruction::Set(MoveInstruction {
                                    src_reg: target_reg,
                                    dst_reg: int as u16,
                                }),
                            }))
                        }
                    }
                }
                Opcode::Call(op) => {
                    let result_reg = self.read_byte(bytecode, idx, *key, Some(op.bits[0]));
                    let ctx_reg = self.read_byte(bytecode, idx, *key, Some(op.bits[1]));
                    let func_reg = self.read_byte(bytecode, idx, *key, Some(op.bits[2]));
                    let args_len = self.read_byte(bytecode, idx, *key, Some(op.bits[3]));

                    let mut vec = Vec::<u16>::new();
                    for _ in 0..args_len {
                        let reg = self.read_byte(bytecode, idx, *key, Some(op.bits[4]));
                        vec.push(reg);
                    }

                    Ok(Instruction::Call(CallInstruction {
                        object_arg: Some(ctx_reg),
                        func_reg,
                        reg_args: vec,
                        ret_reg: result_reg,
                    }))
                }
            }
        } else {
            bail!("opcode not found: {}", opcode);
        }
    }

    fn read_varint(&self, bytecode: &[u8], idx: &mut usize, key: u16) -> Result<usize, Error> {
        let mut i = 0;
        let mut j = 0;

        loop {
            let k = self.read_byte(bytecode, idx, key, None);

            if let Some(shifted) = (k & 127).checked_shl(j) {
                i |= shifted;
            } else {
                bail!("read string len: unexpected left shift");
            }
            j += 7;

            if k & 128 == 0 {
                break;
            }
        }

        Ok(i as usize)
    }

    fn read_byte(&self, bytecode: &[u8], idx: &mut usize, key: u16, magic: Option<u16>) -> u16 {
        let value = bytecode[*idx] as u16;
        *idx += 1;

        let mut result = key ^ (self.offset + value);
        if let Some(magic) = magic {
            result ^= magic;
        }

        result &= 0xFF;
        result
    }

    fn decode_float(&self, bytecode: &[u8], idx: &mut usize, key: u16) -> f64 {
        let upper = self.read_byte(bytecode, idx, key, None) as i64;
        let lower = self.read_byte(bytecode, idx, key, None) as i64;
        let exponent = 2.0_f64.powi((((upper & 255) << 4 | lower >> 4) - 1023) as i32);

        let mut v: f64 = 1.0;
        v /= 2.0;
        let mut mantissa: f64 = 1.0 + (((lower >> 3) & 1) as f64) * v;
        v /= 2.0;
        mantissa += (((lower >> 2) & 1) as f64) * v;
        v /= 2.0;
        mantissa += (((lower >> 1) & 1) as f64) * v;
        v /= 2.0;
        mantissa += (((lower >> 0) & 1) as f64) * v;

        for _ in 0..6 {
            let o = self.read_byte(bytecode, idx, key, None) as i64;
            for s in (0..=7).rev() {
                v /= 2.0;
                mantissa += (v) * (((o >> s) & 1) as f64);
            }
        }

        exponent * (1 + (upper >> 7) * (-2)) as f64 * mantissa
    }
}

type FunctionJump = (usize, u16);
