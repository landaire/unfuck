//! The mapping tables `generate_data.py` derives from the client's codecs.

use crate::interp::builtins::modules::cjkcodecs::data::DecodeTable;
use crate::interp::builtins::modules::cjkcodecs::data::EncodeOverrides;
use crate::interp::builtins::modules::cjkcodecs::data::RangeTable;

macro_rules! decode_table {
    ($name:ident, $file:literal) => {
        pub static $name: DecodeTable = DecodeTable::new(include_bytes!(concat!("data/", $file, ".bin")));
    };
}

macro_rules! encode_overrides {
    ($name:ident, $file:literal) => {
        pub static $name: EncodeOverrides = EncodeOverrides::new(include_bytes!(concat!("data/", $file, "_encode.bin")));
    };
}

// Character sets shared by several codecs, keyed by 7-bit row and cell.
decode_table!(GB2312, "gb2312");
decode_table!(KSX1001, "ksx1001");
decode_table!(JISX0208, "jisx0208");
decode_table!(JISX0212, "jisx0212");
decode_table!(JISX0213_1, "jisx0213_1");
decode_table!(JISX0213_2004, "jisx0213_2004");
decode_table!(JISX0213_2, "jisx0213_2");
decode_table!(JISX0213_2_2000, "jisx0213_2_2000");

// Extensions and deviations keyed by the codes the codecs use.
decode_table!(GBK, "gbk");
decode_table!(GB18030, "gb18030");
decode_table!(CP949, "cp949");
decode_table!(BIG5, "big5");
decode_table!(CP950, "cp950");
decode_table!(BIG5HKSCS, "big5hkscs");
decode_table!(CP932, "cp932");
decode_table!(SHIFT_JIS_2004, "shift_jis_2004");
decode_table!(SHIFT_JISX0213, "shift_jisx0213");
decode_table!(ISO2022_JP_2004, "iso2022_jp_2004");
decode_table!(ISO2022_JP_3, "iso2022_jp_3");
decode_table!(ISO8859_7, "iso8859_7");

pub static GB18030_RANGES: RangeTable = RangeTable::new(include_bytes!("data/gb18030_ranges.bin"));

encode_overrides!(GB2312_ENCODE, "gb2312");
encode_overrides!(GBK_ENCODE, "gbk");
encode_overrides!(GB18030_ENCODE, "gb18030");
encode_overrides!(BIG5_ENCODE, "big5");
encode_overrides!(CP950_ENCODE, "cp950");
encode_overrides!(BIG5HKSCS_ENCODE, "big5hkscs");
encode_overrides!(SHIFT_JIS_ENCODE, "shift_jis");
encode_overrides!(CP932_ENCODE, "cp932");
encode_overrides!(EUC_JP_ENCODE, "euc_jp");
encode_overrides!(SHIFT_JIS_2004_ENCODE, "shift_jis_2004");
encode_overrides!(SHIFT_JISX0213_ENCODE, "shift_jisx0213");
encode_overrides!(EUC_JIS_2004_ENCODE, "euc_jis_2004");
encode_overrides!(EUC_JISX0213_ENCODE, "euc_jisx0213");
encode_overrides!(EUC_KR_ENCODE, "euc_kr");
encode_overrides!(CP949_ENCODE, "cp949");
encode_overrides!(JOHAB_ENCODE, "johab");
