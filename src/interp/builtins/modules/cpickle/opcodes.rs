//! The pickle opcode bytes of protocols 0 through 2.

/// One pickle instruction, named by what it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Op {
    Mark = b'(',
    Stop = b'.',
    Pop = b'0',
    PopMark = b'1',
    Dup = b'2',
    Float = b'F',
    BinFloat = b'G',
    Int = b'I',
    BinInt = b'J',
    BinInt1 = b'K',
    BinInt2 = b'M',
    Long = b'L',
    None = b'N',
    PersistentId = b'P',
    BinPersistentId = b'Q',
    Reduce = b'R',
    String = b'S',
    BinString = b'T',
    ShortBinString = b'U',
    Unicode = b'V',
    BinUnicode = b'X',
    Append = b'a',
    Build = b'b',
    Global = b'c',
    Dict = b'd',
    EmptyDict = b'}',
    Appends = b'e',
    Get = b'g',
    BinGet = b'h',
    LongBinGet = b'j',
    Inst = b'i',
    List = b'l',
    EmptyList = b']',
    Obj = b'o',
    Put = b'p',
    BinPut = b'q',
    LongBinPut = b'r',
    SetItem = b's',
    Tuple = b't',
    EmptyTuple = b')',
    SetItems = b'u',
    Proto = 0x80,
    NewObj = 0x81,
    Ext1 = 0x82,
    Ext2 = 0x83,
    Ext4 = 0x84,
    Tuple1 = 0x85,
    Tuple2 = 0x86,
    Tuple3 = 0x87,
    NewTrue = 0x88,
    NewFalse = 0x89,
    Long1 = 0x8a,
    Long4 = 0x8b,
}

impl Op {
    /// Every opcode.
    const ALL: [Self; 53] = [
        Self::Mark,
        Self::Stop,
        Self::Pop,
        Self::PopMark,
        Self::Dup,
        Self::Float,
        Self::BinFloat,
        Self::Int,
        Self::BinInt,
        Self::BinInt1,
        Self::BinInt2,
        Self::Long,
        Self::None,
        Self::PersistentId,
        Self::BinPersistentId,
        Self::Reduce,
        Self::String,
        Self::BinString,
        Self::ShortBinString,
        Self::Unicode,
        Self::BinUnicode,
        Self::Append,
        Self::Build,
        Self::Global,
        Self::Dict,
        Self::EmptyDict,
        Self::Appends,
        Self::Get,
        Self::BinGet,
        Self::LongBinGet,
        Self::Inst,
        Self::List,
        Self::EmptyList,
        Self::Obj,
        Self::Put,
        Self::BinPut,
        Self::LongBinPut,
        Self::SetItem,
        Self::Tuple,
        Self::EmptyTuple,
        Self::SetItems,
        Self::Proto,
        Self::NewObj,
        Self::Ext1,
        Self::Ext2,
        Self::Ext4,
        Self::Tuple1,
        Self::Tuple2,
        Self::Tuple3,
        Self::NewTrue,
        Self::NewFalse,
        Self::Long1,
        Self::Long4,
    ];

    /// The opcode of each byte value.
    const BY_BYTE: [Option<Self>; 256] = {
        let mut table = [None; 256];
        let mut index = 0;
        while index < Self::ALL.len() {
            let op = Self::ALL[index];
            table[op as usize] = Some(op);
            index += 1;
        }
        table
    };

    pub(super) fn from_byte(byte: u8) -> Option<Self> {
        Self::BY_BYTE[usize::from(byte)]
    }

    pub(super) fn byte(self) -> u8 {
        self as u8
    }
}
