//! Message digests shared by `_hashlib`, `_md5`, `_sha`, `_sha256`, and
//! `_sha512`.

use md5::Md5;
use sha1::Sha1;
use sha2::Digest;
use sha2::Sha224;
use sha2::Sha256;
use sha2::Sha384;
use sha2::Sha512;

use crate::interp::builtins::modules::binascii::is_native_object;
use crate::interp::builtins::modules::codecs::args::string_or_buffer;
use crate::interp::error::PyResult;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Algorithm {
    pub fn digest_size(self) -> u8 {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub fn block_size(self) -> u8 {
        match self {
            Self::Md5 | Self::Sha1 | Self::Sha224 | Self::Sha256 => 64,
            Self::Sha384 | Self::Sha512 => 128,
        }
    }
}

/// A running digest computation.
#[derive(Clone)]
pub enum Hasher {
    Md5(Md5),
    Sha1(Sha1),
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    fn new(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Md5 => Self::Md5(Md5::new()),
            Algorithm::Sha1 => Self::Sha1(Sha1::new()),
            Algorithm::Sha224 => Self::Sha224(Sha224::new()),
            Algorithm::Sha256 => Self::Sha256(Sha256::new()),
            Algorithm::Sha384 => Self::Sha384(Sha384::new()),
            Algorithm::Sha512 => Self::Sha512(Sha512::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Md5(hasher) => hasher.update(data),
            Self::Sha1(hasher) => hasher.update(data),
            Self::Sha224(hasher) => hasher.update(data),
            Self::Sha256(hasher) => hasher.update(data),
            Self::Sha384(hasher) => hasher.update(data),
            Self::Sha512(hasher) => hasher.update(data),
        }
    }

    /// The digest of the input so far; the computation can continue.
    fn digest(&self) -> Vec<u8> {
        match self.clone() {
            Self::Md5(hasher) => hasher.finalize().to_vec(),
            Self::Sha1(hasher) => hasher.finalize().to_vec(),
            Self::Sha224(hasher) => hasher.finalize().to_vec(),
            Self::Sha256(hasher) => hasher.finalize().to_vec(),
            Self::Sha384(hasher) => hasher.finalize().to_vec(),
            Self::Sha512(hasher) => hasher.finalize().to_vec(),
        }
    }
}

/// The input a hash object has consumed.
#[derive(Clone)]
pub enum HashState {
    Known(Hasher),
    /// Some input was unknown, so the digest is too.
    Unknown,
}

impl HashState {
    pub fn new(algorithm: Algorithm) -> Self {
        Self::Known(Hasher::new(algorithm))
    }

    /// Consumes `data`; `None` is unknown input.
    pub fn update(&mut self, data: Option<&[u8]>) {
        match (self, data) {
            (Self::Known(hasher), Some(data)) => hasher.update(data),
            (state, None) => *state = Self::Unknown,
            (Self::Unknown, Some(_)) => {
                // Unknown input already determines the digest.
            }
        }
    }

    pub fn digest(&self) -> Option<Vec<u8>> {
        match self {
            Self::Known(hasher) => Some(hasher.digest()),
            Self::Unknown => None,
        }
    }
}

/// The value of `digest()` on an object of type `type_name`.
pub fn digest_value(state: &HashState, type_name: &str) -> Value {
    match state.digest() {
        Some(digest) => Value::Str(PyBytes::new(digest)),
        None => Value::unknown(format!("{type_name}.digest")),
    }
}

/// The value of `hexdigest()`, in lowercase, on an object of type
/// `type_name`.
pub fn hexdigest_value(state: &HashState, type_name: &str) -> Value {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let Some(digest) = state.digest() else {
        return Value::unknown(format!("{type_name}.hexdigest"));
    };

    let mut text = Vec::with_capacity(digest.len() * 2);
    for byte in digest {
        text.push(DIGITS[usize::from(byte >> 4)]);
        text.push(DIGITS[usize::from(byte & 0xf)]);
    }

    Value::Str(PyBytes::new(text))
}

/// An `s*` data argument at `position` of `function`; `None` when it is
/// unknown.
pub fn data_argument(vm: &Vm, value: &Value, function: &str, position: usize) -> PyResult<Option<PyBytes>> {
    if value.is_unknown() {
        return Ok(None);
    }
    if is_native_object(vm, value) {
        return Err(vm.halt_unsupported(format!("{function}() of a native buffer object")));
    }

    string_or_buffer(vm, function, position, value).map(Some)
}

/// An optional `s*` data argument, where absence is empty input; `None`
/// when it is unknown.
pub fn optional_data_argument(vm: &Vm, value: Option<&Value>, function: &str, position: usize) -> PyResult<Option<PyBytes>> {
    match value {
        Some(value) => data_argument(vm, value, function, position),
        None => Ok(Some(PyBytes::from(""))),
    }
}

/// HMAC (RFC 2104) under one key, with the padded key already absorbed.
struct Hmac {
    inner: Hasher,
    outer: Hasher,
}

impl Hmac {
    fn new(algorithm: Algorithm, key: &[u8]) -> Self {
        let block_size = usize::from(algorithm.block_size());
        let mut block = if key.len() > block_size {
            let mut hasher = Hasher::new(algorithm);
            hasher.update(key);
            hasher.digest()
        } else {
            key.to_vec()
        };
        block.resize(block_size, 0);

        for byte in &mut block {
            *byte ^= 0x36;
        }
        let mut inner = Hasher::new(algorithm);
        inner.update(&block);

        // 0x36 ^ 0x6a == 0x5c turns the inner pad into the outer pad.
        for byte in &mut block {
            *byte ^= 0x6a;
        }
        let mut outer = Hasher::new(algorithm);
        outer.update(&block);

        Self { inner, outer }
    }

    fn mac(&self, message: &[&[u8]]) -> Vec<u8> {
        let mut inner = self.inner.clone();
        for part in message {
            inner.update(part);
        }

        let mut outer = self.outer.clone();
        outer.update(&inner.digest());

        outer.digest()
    }
}

/// PBKDF2 (RFC 2898) with HMAC as the pseudorandom function.
pub fn pbkdf2_hmac(algorithm: Algorithm, password: &[u8], salt: &[u8], iterations: u32, key_length: usize) -> Vec<u8> {
    let hmac = Hmac::new(algorithm, password);
    let mut key = Vec::with_capacity(key_length);
    let mut block_index: u32 = 1;

    while key.len() < key_length {
        let mut round = hmac.mac(&[salt, &block_index.to_be_bytes()]);
        let mut block = round.clone();

        for _ in 1..iterations {
            round = hmac.mac(&[&round]);
            for (target, byte) in block.iter_mut().zip(&round) {
                *target ^= byte;
            }
        }

        let take = block.len().min(key_length - key.len());
        key.extend_from_slice(&block[..take]);
        block_index = block_index.wrapping_add(1);
    }

    key
}
