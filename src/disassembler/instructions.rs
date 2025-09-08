use crate::parser::magic_bits::{BinaryOperator, UnaryOperator};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    String(String),
    Undefined,
}

impl Value {
    pub fn as_string(&self) -> Option<&String> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RegisteredFunction {
    pub start: u64,
    pub end: u64,
    pub body: Vec<(usize, Instruction)>,
    pub values: Vec<Value>,
}

#[derive(Clone, Debug)]
pub enum Instruction {
    RegisterVMFunc(RegisterVMFunctionInstruction),
    Heap(HeapInstruction),
    NewLiteral(NewLiteralInstruction),
    Call(CallInstruction),
    CallNoCtx(CallInstruction),
    Pop(PopInstruction),
    Throw(ThrowInstruction),
    BindOpcode(BindOpcodeInstruction),
    Push(ArrayPushInstruction),
    GetProperty(GetPropertyInstruction),
    SetProperty(SetPropertyInstruction),
    Swap(RegisterSwapInstruction),
    Jump(JumpInstruction),
    ConditionalJump(ConditionalJumpInstruction),
    Move(MoveInstruction),
    NewObject(NewInstruction),
    NewArray(NewInstruction),
    Binary(BinaryInstruction),
    Unary(UnaryInstruction),
    SplicePop(SplicePopInstruction),

    // not actual vm opcodes (for very malicious purposes...)
    Nop,
    Return(ReturnInstruction),
}

#[derive(Clone, Debug)]
pub struct ReturnInstruction {
    pub return_register: u16,
}

#[derive(Clone, Debug)]
pub struct BindOpcodeInstruction {
    pub reg: u16,
    pub opcode: u16,
    pub arg: u16,
}

#[derive(Clone, Debug)]
pub struct SplicePopInstruction {
    pub arrays: Vec<u16>,
    pub reg: u16,
}

#[derive(Clone, Debug)]
pub struct BinaryInstruction {
    pub op: BinaryOperator,
    pub a: u16,
    pub b: u16,
    pub ret_reg: u16,
}

#[derive(Clone, Debug)]
pub enum HeapSubInstruction {
    Get(MoveInstruction),
    Set(MoveInstruction),
    Init(Vec<usize>),
}

#[derive(Clone, Debug)]
pub struct HeapInstruction {
    pub sub_instruction: HeapSubInstruction,
}

#[derive(Clone, Debug)]
pub struct ArrayPushInstruction {
    pub arr_reg: u16,
    pub val_reg: u16,
}

#[derive(Clone, Debug)]
pub struct MoveInstruction {
    pub src_reg: u16,
    pub dst_reg: u16,
}

#[derive(Clone, Debug)]
pub struct PopInstruction {
    pub arr_reg: u16,
    pub ret_reg: u16,
}

#[derive(Clone, Debug)]
pub struct CallInstruction {
    pub object_arg: Option<u16>,
    pub func_reg: u16,
    pub reg_args: Vec<u16>,
    pub ret_reg: u16,
}

#[derive(Clone, Debug)]
pub struct RegisterVMFunctionInstruction {
    pub jump: JumpInstruction,
    pub ret_reg: u16,
}

#[derive(Clone, Debug)]
pub struct GetPropertyInstruction {
    pub obj_reg: u16,
    pub key_reg: u16,
    pub ret_reg: u16,
}

#[derive(Clone, Debug)]
pub struct RegisterSwapInstruction {
    pub first: u16,
    pub second: u16,
}

#[derive(Clone, Debug)]
pub struct SetPropertyInstruction {
    pub obj_reg: u16,
    pub key_reg: u16,
    pub val_reg: u16,
}

#[derive(Clone, Debug)]
pub enum LiteralInstructionType {
    Null,
    Undefined,
    NaN,
    Infinity,
    True,
    False,
    Byte(u16), // should be an u8 but dw
    Integer(i64),
    Float(f64),
    String(String),
    ByteArray(Vec<u16>),        // should be an u8 but dw
    CopyState(JumpInstruction),
    Regexp((String /*pattern*/, String /*flags*/)),
}

#[derive(Clone, Debug)]
pub struct NewLiteralInstruction {
    pub data: LiteralInstructionType,
    pub ret_reg: u16,
}

#[derive(Clone, Debug)]
pub struct UnaryInstruction {
    pub op: UnaryOperator,
    pub a: u16,
    pub ret_reg: u16,
}

#[derive(Clone, Debug)]
pub struct NewInstruction {
    pub ret_reg: u16,
}

#[derive(Clone, Debug)]
pub struct JumpInstruction {
    pub pos: usize,
    pub new_key: u16,
}

#[derive(Clone, Debug)]
pub struct ThrowInstruction {
    pub exception_reg: u16,
}

#[derive(Clone, Debug)]
pub struct ConditionalJumpInstruction {
    pub jump: JumpInstruction,
    pub test_reg: u16,
}

pub trait WithDst {
    fn get_dst_reg(&self) -> Option<u16>;
}

impl WithDst for BinaryInstruction {
    fn get_dst_reg(&self) -> Option<u16> {
        Some(self.ret_reg)
    }
}

impl WithDst for UnaryInstruction {
    fn get_dst_reg(&self) -> Option<u16> {
        Some(self.ret_reg)
    }
}

impl WithDst for NewInstruction {
    fn get_dst_reg(&self) -> Option<u16> {
        Some(self.ret_reg)
    }
}

impl WithDst for MoveInstruction {
    fn get_dst_reg(&self) -> Option<u16> {
        Some(self.dst_reg)
    }
}

impl WithDst for RegisterVMFunctionInstruction {
    fn get_dst_reg(&self) -> Option<u16> {
        Some(self.ret_reg)
    }
}

impl WithDst for GetPropertyInstruction {
    fn get_dst_reg(&self) -> Option<u16> {
        Some(self.ret_reg)
    }
}

impl WithDst for NewLiteralInstruction {
    fn get_dst_reg(&self) -> Option<u16> {
        Some(self.ret_reg)
    }
}

impl WithDst for PopInstruction {
    fn get_dst_reg(&self) -> Option<u16> {
        Some(self.ret_reg)
    }
}

impl WithDst for BindOpcodeInstruction {
    fn get_dst_reg(&self) -> Option<u16> {
        Some(self.reg)
    }
}

impl WithDst for CallInstruction {
    fn get_dst_reg(&self) -> Option<u16> {
        Some(self.ret_reg)
    }
}

impl WithDst for HeapInstruction {
    fn get_dst_reg(&self) -> Option<u16> {
        match &self.sub_instruction {
            HeapSubInstruction::Get(mv) => mv.get_dst_reg(),
            HeapSubInstruction::Set(mv) => mv.get_dst_reg(),
            HeapSubInstruction::Init(_) => None,
        }
    }
}

impl WithDst for Instruction {
    fn get_dst_reg(&self) -> Option<u16> {
        match self {
            Instruction::Move(op) => op.get_dst_reg(),
            Instruction::Pop(op) => op.get_dst_reg(),
            Instruction::GetProperty(op) => op.get_dst_reg(),
            Instruction::NewLiteral(op) => op.get_dst_reg(),
            Instruction::Call(op) => op.get_dst_reg(),
            Instruction::CallNoCtx(op) => op.get_dst_reg(),
            Instruction::NewObject(op) => op.get_dst_reg(),
            Instruction::NewArray(op) => op.get_dst_reg(),
            Instruction::RegisterVMFunc(op) => op.get_dst_reg(),
            Instruction::Binary(op) => op.get_dst_reg(),
            Instruction::Unary(op) => op.get_dst_reg(),
            Instruction::Heap(op) => op.get_dst_reg(),
            Instruction::BindOpcode(op) => op.get_dst_reg(),
            _ => None,
        }
    }
}

pub trait UsedRegisters {
    fn get_used_registers(&self) -> Vec<u16>;
}

impl UsedRegisters for RegisterVMFunctionInstruction {
    fn get_used_registers(&self) -> Vec<u16> {
        vec![self.ret_reg]
    }
}

impl UsedRegisters for MoveInstruction {
    fn get_used_registers(&self) -> Vec<u16> {
        vec![self.src_reg, self.dst_reg]
    }
}

impl UsedRegisters for ArrayPushInstruction {
    fn get_used_registers(&self) -> Vec<u16> {
        vec![self.arr_reg, self.val_reg]
    }
}

impl UsedRegisters for PopInstruction {
    fn get_used_registers(&self) -> Vec<u16> {
        vec![self.arr_reg, self.ret_reg]
    }
}

impl UsedRegisters for CallInstruction {
    fn get_used_registers(&self) -> Vec<u16> {
        let mut vec = Vec::from([self.func_reg, self.ret_reg]);
        vec.extend(self.reg_args.clone());

        if let Some(reg) = self.object_arg {
            vec.push(reg);
        }

        vec
    }
}

impl UsedRegisters for ThrowInstruction {
    fn get_used_registers(&self) -> Vec<u16> {
        vec![self.exception_reg]
    }
}

impl UsedRegisters for ConditionalJumpInstruction {
    fn get_used_registers(&self) -> Vec<u16> {
        vec![self.test_reg]
    }
}

impl UsedRegisters for HeapInstruction {
    fn get_used_registers(&self) -> Vec<u16> {
        match &self.sub_instruction {
            HeapSubInstruction::Get(mv) => vec![mv.dst_reg],
            HeapSubInstruction::Set(mv) => vec![mv.src_reg],
            HeapSubInstruction::Init(_) => vec![],
        }
    }
}

impl UsedRegisters for GetPropertyInstruction {
    fn get_used_registers(&self) -> Vec<u16> {
        vec![self.obj_reg, self.key_reg, self.ret_reg]
    }
}

impl UsedRegisters for SetPropertyInstruction {
    fn get_used_registers(&self) -> Vec<u16> {
        vec![self.obj_reg, self.key_reg, self.val_reg]
    }
}

impl UsedRegisters for NewLiteralInstruction {
    fn get_used_registers(&self) -> Vec<u16> {
        vec![self.ret_reg]
    }
}

impl UsedRegisters for UnaryInstruction {
    fn get_used_registers(&self) -> Vec<u16> {
        vec![self.a, self.ret_reg]
    }
}

impl UsedRegisters for NewInstruction {
    fn get_used_registers(&self) -> Vec<u16> {
        vec![self.ret_reg]
    }
}

impl UsedRegisters for BinaryInstruction {
    fn get_used_registers(&self) -> Vec<u16> {
        vec![self.a, self.b, self.ret_reg]
    }
}

impl UsedRegisters for SplicePopInstruction {
    fn get_used_registers(&self) -> Vec<u16> {
        vec![self.reg]
    }
}

impl UsedRegisters for BindOpcodeInstruction {
    fn get_used_registers(&self) -> Vec<u16> {
        vec![self.reg]
    }
}

impl UsedRegisters for RegisterSwapInstruction {
    fn get_used_registers(&self) -> Vec<u16> {
        vec![self.first, self.second]
    }
}

impl UsedRegisters for Instruction {
    fn get_used_registers(&self) -> Vec<u16> {
        match self {
            Instruction::Move(op) => op.get_used_registers(),
            Instruction::Pop(op) => op.get_used_registers(),
            Instruction::GetProperty(op) => op.get_used_registers(),
            Instruction::NewLiteral(op) => op.get_used_registers(),
            Instruction::Call(op) => op.get_used_registers(),
            Instruction::CallNoCtx(op) => op.get_used_registers(),
            Instruction::NewObject(op) => op.get_used_registers(),
            Instruction::NewArray(op) => op.get_used_registers(),
            Instruction::Heap(op) => op.get_used_registers(),
            Instruction::BindOpcode(op) => op.get_used_registers(),
            Instruction::Throw(op) => op.get_used_registers(),
            Instruction::SplicePop(op) => op.get_used_registers(),
            Instruction::Push(op) => op.get_used_registers(),
            Instruction::Unary(op) => op.get_used_registers(),
            Instruction::Binary(op) => op.get_used_registers(),
            Instruction::RegisterVMFunc(op) => op.get_used_registers(),
            Instruction::ConditionalJump(op) => op.get_used_registers(),
            Instruction::SetProperty(op) => op.get_used_registers(),
            Instruction::Swap(op) => op.get_used_registers(),
            _ => vec![],
        }
    }
}
