use std::path::Path;

use py27_marshal::Code;
use serde::Serialize;

#[derive(Serialize, Debug)]
pub enum StringType {
    Const,
    VarName,
    Name,
}

#[derive(Serialize, Debug)]
pub struct CodeObjString<'a> {
    string_type: StringType,
    pyc_file_name: &'a Path,
    embedded_file_name: String,
    object_name: String,
    value: String,
}

impl<'a> CodeObjString<'a> {
    pub fn new(
        code_obj: &Code,
        pyc_file_name: &'a Path,
        typ: StringType,
        value: &str,
    ) -> CodeObjString<'a> {
        // Ensure this string is unescaped
        let value = if let Ok(decoded_str) = stfu8::decode_u8(value) {
            if let Ok(s) = std::str::from_utf8(decoded_str.as_slice()) {
                s.to_string()
            } else {
                value.to_string()
            }
        } else {
            value.to_string()
        };

        CodeObjString {
            string_type: typ,
            pyc_file_name,
            embedded_file_name: code_obj.filename.to_string(),
            object_name: code_obj.name.to_string(),
            value,
        }
    }
}
