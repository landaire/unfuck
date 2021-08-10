use py_marshal::read::errors::ErrorKind;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("unexpected data type while processing `{0}`: {1:?}")]
    ObjectError(&'static str, py_marshal::Obj),
    #[error("error disassembling bytecode: {0}")]
    DisassemblerError(#[from] pydis::error::DecodeError),
    #[error("input is not a valid code object")]
    InvalidCodeObject,
    #[error("error executing bytecode: {0}")]
    ExecutionError(#[from] ExecutionError),
    #[error("error parsing data: {0}")]
    ParserError(#[from] ErrorKind),
}

#[derive(Error, Debug)]
pub enum ExecutionError {
    #[error("complex opcode/object type encountered. Opcode: {0:?}, Object Type: {1:?}")]
    ComplexExpression(
        pydis::opcode::Instruction<pydis::opcode::Python27>,
        Option<py_marshal::Type>,
    ),

    #[error("unsupported instruction encountered: {0:?}")]
    UnsupportedOpcode(pydis::opcode::Python27),
}
