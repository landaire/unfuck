use py27_marshal::read::errors::ErrorKind;
use pydis::opcode::py27::{self};
use pydis::prelude::Opcode;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error<O: 'static + Opcode<Mnemonic = py27::Mnemonic>> {
    #[error("unexpected data type while processing `{0}`: {1:?}")]
    ObjectError(&'static str, py27_marshal::Obj),
    #[error("error disassembling bytecode: {0}")]
    DisassemblerError(#[from] pydis::error::DecodeError),
    #[error("input is not a valid code object")]
    InvalidCodeObject,
    #[error("error executing bytecode: {0}")]
    ExecutionError(#[from] ExecutionError<O>),
    #[error("error parsing data: {0}")]
    ParserError(#[from] ErrorKind),
}

#[derive(Error, Debug)]
pub enum ExecutionError<O: Opcode<Mnemonic = py27::Mnemonic>> {
    #[error("complex opcode/object type encountered. Opcode: {0:?}, Object Type: {1:?}")]
    ComplexExpression(pydis::opcode::Instruction<O>, Option<py27_marshal::Type>),

    #[error("unsupported instruction encountered: {0:?}")]
    UnsupportedOpcode(O),
}
