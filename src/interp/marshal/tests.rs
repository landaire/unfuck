use std::path::Path;

use super::*;
use crate::interp::complex::Complex;
use crate::interp::hash::LongWidth;
use crate::interp::marshal::writer::Marshalled;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::ModuleCode;
use crate::interp::vm::ModuleSource;
use crate::interp::vm::Vm;
use crate::interp::vm::VmConfig;

struct NoModules;

impl ModuleSource for NoModules {
    fn find(&self, _name: &str) -> Option<ModuleCode> {
        None
    }
}

/// A marshal stream read one object at a time.
struct Stream<'a> {
    bytes: &'a [u8],
    position: usize,
    /// The interned strings read so far, which `R` names by index.
    interned: Vec<&'a [u8]>,
}

impl<'a> Stream<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0, interned: Vec::new() }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let end = self.position.checked_add(count).filter(|end| *end <= self.bytes.len()).ok_or_else(|| format!("truncated at {}", self.position))?;
        let taken = &self.bytes[self.position..end];
        self.position = end;

        Ok(taken)
    }

    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn peek(&self) -> Result<u8, String> {
        self.bytes.get(self.position).copied().ok_or_else(|| format!("truncated at {}", self.position))
    }

    fn int(&mut self) -> Result<i32, String> {
        let bytes = self.take(4)?;

        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn length(&mut self) -> Result<usize, String> {
        let at = self.position;

        usize::try_from(self.int()?).map_err(|_| format!("negative length at {at}"))
    }

    /// The bytes of an `s`, `t` or `u` object.
    fn string(&mut self) -> Result<&'a [u8], String> {
        let length = self.length()?;

        self.take(length)
    }

    /// The interned string an `R` object names.
    fn reference(&mut self) -> Result<&'a [u8], String> {
        let at = self.position;
        let index = self.length()?;

        self.interned.get(index).copied().ok_or_else(|| format!("reference {index} out of range at {at}"))
    }
}

/// A marshalled fixture and the interpreter's rewrite of it, walked
/// together. They match byte for byte, except that a distinct empty string
/// (`s` of length 0) loads as the shared interned one: it is written as `t`
/// of length 0, or as a reference to an interned empty string. Once it is
/// interned, a later interned empty string (`t`) is written as a reference.
struct RewriteWalk<'a> {
    original: Stream<'a>,
    rewritten: Stream<'a>,
}

impl RewriteWalk<'_> {
    fn object(&mut self) -> Result<(), String> {
        let at = self.original.position;
        let kind = self.original.byte()?;
        let rewritten = self.rewritten.byte()?;
        if (kind == b's' && rewritten != b's') || (kind == b't' && rewritten == b'R') {
            return self.reloaded_empty(kind, rewritten, at);
        }
        if kind != rewritten {
            return Err(format!("{:?} at {at} written as {:?}", char::from(kind), char::from(rewritten)));
        }

        match kind {
            b'0' | b'N' | b'F' | b'T' | b'S' | b'.' => Ok(()),
            b'i' => self.same(4),
            b'I' | b'g' => self.same(8),
            b'y' => self.same(16),
            b'f' => self.short_text(),
            b'x' => {
                self.short_text()?;
                self.short_text()
            }
            b'l' => {
                let digits = self.original.int()?;
                Self::same_value(digits, self.rewritten.int()?, at)?;
                self.same(digits.unsigned_abs() as usize * 2)
            }
            b's' | b'u' => {
                let original = self.original.string()?;
                Self::same_value(original, self.rewritten.string()?, at)
            }
            b't' => {
                let original = self.original.string()?;
                let rewritten = self.rewritten.string()?;
                self.original.interned.push(original);
                self.rewritten.interned.push(rewritten);
                Self::same_value(original, rewritten, at)
            }
            b'R' => {
                let original = self.original.reference()?;
                Self::same_value(original, self.rewritten.reference()?, at)
            }
            b'(' | b'[' | b'<' | b'>' => {
                let length = self.original.length()?;
                Self::same_value(length, self.rewritten.length()?, at)?;
                for _ in 0..length {
                    self.object()?;
                }
                Ok(())
            }
            b'{' => {
                while self.original.peek()? != b'0' {
                    self.object()?;
                    self.object()?;
                }
                self.object()
            }
            // Four counts and flags, eight objects, the first line number,
            // and the line number table.
            b'c' => {
                self.same(16)?;
                for _ in 0..8 {
                    self.object()?;
                }
                self.same(4)?;
                self.object()
            }
            other => Err(format!("unknown type {:?} at {at}", char::from(other))),
        }
    }

    /// The rewrite of an empty string, whose type bytes are read.
    fn reloaded_empty(&mut self, kind: u8, rewritten: u8, at: usize) -> Result<(), String> {
        let original = self.original.string()?;
        if !original.is_empty() {
            return Err(format!("non-empty string at {at} written as {:?}", char::from(rewritten)));
        }
        if kind == b't' {
            self.original.interned.push(original);
        }
        let interned = match rewritten {
            b't' => {
                let interned = self.rewritten.string()?;
                self.rewritten.interned.push(interned);
                interned
            }
            b'R' => self.rewritten.reference()?,
            other => return Err(format!("empty string at {at} written as {:?}", char::from(other))),
        };
        if !interned.is_empty() {
            return Err(format!("empty string at {at} written as a non-empty interned string"));
        }

        Ok(())
    }

    fn same(&mut self, count: usize) -> Result<(), String> {
        let at = self.original.position;
        let original = self.original.take(count)?;

        Self::same_value(original, self.rewritten.take(count)?, at)
    }

    /// A length byte and that many bytes, as `f` and `x` write a float.
    fn short_text(&mut self) -> Result<(), String> {
        let length = self.original.peek()?;

        self.same(1 + usize::from(length))
    }

    fn same_value<T: PartialEq + std::fmt::Debug>(original: T, rewritten: T, at: usize) -> Result<(), String> {
        if original != rewritten {
            return Err(format!("{original:?} at {at} written as {rewritten:?}"));
        }

        Ok(())
    }

    fn finish(&self) -> Result<(), String> {
        if self.original.position != self.original.bytes.len() || self.rewritten.position != self.rewritten.bytes.len() {
            return Err(format!("trailing data after {} and {} bytes", self.original.position, self.rewritten.position));
        }

        Ok(())
    }
}

/// An interpreter with the 64-bit C `long` of the Linux build that wrote
/// `SPECIAL_CONSTANTS`.
fn linux_vm() -> Vm {
    let mut config = VmConfig::windows_x64();
    config.long_width = LongWidth::Bits64;

    Vm::new(config, Box::new(NoModules)).unwrap_or_else(|_| panic!("interpreter bootstrap failed"))
}

fn round_trip(vm: &Vm, data: &[u8]) -> Vec<u8> {
    let value = loads(vm, data).unwrap_or_else(|_| panic!("the data loads"));

    match dumps(vm, &value, VERSION) {
        Ok(Marshalled::Written(bytes)) => bytes,
        _ => panic!("the value marshals"),
    }
}

#[test]
fn round_trips_cpython_fixtures() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/interp");
    let vm = Vm::new(VmConfig::windows_x64(), Box::new(NoModules)).unwrap_or_else(|_| panic!("interpreter bootstrap failed"));

    for entry in std::fs::read_dir(root.join("cases")).unwrap() {
        let path = entry.unwrap().path();
        if !path.extension().is_some_and(|extension| extension == "marshal") {
            continue;
        }

        let data = std::fs::read(&path).unwrap();
        let written = round_trip(&vm, &data);
        let mut walk = RewriteWalk { original: Stream::new(&data), rewritten: Stream::new(&written) };
        if let Err(error) = walk.object().and_then(|()| walk.finish()) {
            panic!("{} does not round-trip: {error}", path.display());
        }
    }
}

/// `marshal.dumps(compile(SOURCE, 'm.py', 'exec'))` of the reference
/// CPython 2.7.18 (Linux x64):
///
/// ```python
/// SOURCE = ('a = 1.5j\nb = 10**30\nc = -0.0\nd = u"\\U0001f600x"\n'
///           'e = u"\\ud800"\nf = -(2**40)\ng = -10**30\nh = 0L\n')
/// ```
const SPECIAL_CONSTANTS: &[u8] = b"c\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00@\x00\x00\x00s4\x00\x00\x00d\x00\x00Z\x00\x00d\x0a\x00Z\x01\x00d\x03\x00Z\x02\x00d\x04\x00Z\x03\x00d\x05\x00Z\x04\x00d\x0c\x00Z\x05\x00d\x0e\x00Z\x06\x00d\x08\x00Z\x07\x00d\x09\x00S(\x0f\x00\x00\x00y\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf8?i\x0a\x00\x00\x00i\x1e\x00\x00\x00g\x00\x00\x00\x00\x00\x00\x00\x80u\x05\x00\x00\x00\xf0\x9f\x98\x80xu\x03\x00\x00\x00\xed\xa0\x80i\x02\x00\x00\x00i(\x00\x00\x00l\x00\x00\x00\x00Nl\x07\x00\x00\x00\x00\x00\x00\x00\xa97\xa73\x04M\x93e'\x03I\x00\x00\x00\x00\x00\x01\x00\x00I\x00\x00\x00\x00\x00\xff\xff\xffl\x07\x00\x00\x00\x00\x00\x00\x00\xa97\xa73\x04M\x93e'\x03l\xf9\xff\xff\xff\x00\x00\x00\x00\xa97\xa73\x04M\x93e'\x03(\x08\x00\x00\x00t\x01\x00\x00\x00at\x01\x00\x00\x00bt\x01\x00\x00\x00ct\x01\x00\x00\x00dt\x01\x00\x00\x00et\x01\x00\x00\x00ft\x01\x00\x00\x00gt\x01\x00\x00\x00h(\x00\x00\x00\x00(\x00\x00\x00\x00(\x00\x00\x00\x00s\x04\x00\x00\x00m.pyt\x08\x00\x00\x00<module>\x01\x00\x00\x00s\x0e\x00\x00\x00\x06\x01\x06\x01\x06\x01\x06\x01\x06\x01\x06\x01\x06\x01";

#[test]
fn round_trips_special_constants() {
    let vm = linux_vm();
    let value = loads(&vm, SPECIAL_CONSTANTS).unwrap_or_else(|_| panic!("the code loads"));
    let Value::Object(object) = &value else {
        panic!("a code object");
    };
    let Payload::Code(code) = &object.payload else {
        panic!("a code object");
    };

    let consts = &code.consts;
    assert_eq!(vm.as_complex(&consts[0]), Some(Complex::new(0.0, 1.5)));
    assert!(matches!(consts[3], Value::Float(value) if value.to_bits() == (-0.0f64).to_bits()));
    assert!(matches!(&consts[4], Value::Unicode(text) if text.units() == [0xD83D, 0xDE00, u16::from(b'x')]));
    assert!(matches!(&consts[5], Value::Unicode(text) if text.units() == [0xD800]));
    assert!(matches!(consts[12], Value::Int(value) if value == -(1 << 40)));
    assert_eq!(round_trip(&vm, SPECIAL_CONSTANTS), SPECIAL_CONSTANTS);
}

/// `marshal.dumps(compile('x = 1j\n', 's', 'exec'), 1)` with the
/// imaginary part written as `b"1\0"`, which the C reader cuts at the
/// NUL.
#[test]
fn text_complex_constants_stop_at_nul() {
    const CODE: &[u8] = b"c\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00@\x00\x00\x00s\n\x00\x00\x00d\x00\x00Z\x00\x00d\x01\x00S(\x02\x00\x00\x00x\x010\x021\x00N(\x01\x00\x00\x00t\x01\x00\x00\x00x(\x00\x00\x00\x00(\x00\x00\x00\x00(\x00\x00\x00\x00t\x01\x00\x00\x00st\x08\x00\x00\x00<module>\x01\x00\x00\x00t\x00\x00\x00\x00";

    let vm = Vm::new(VmConfig::windows_x64(), Box::new(NoModules)).unwrap_or_else(|_| panic!("interpreter bootstrap failed"));
    let Ok(code) = load_code(&vm, CODE) else {
        panic!("code object loads");
    };
    let Payload::Code(code) = &code.payload else {
        panic!("a code object");
    };

    assert_eq!(code.consts.first().and_then(|value| vm.as_complex(value)), Some(Complex::new(0.0, 1.0)));
}
