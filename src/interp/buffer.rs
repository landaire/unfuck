//! The buffer interfaces of CPython 2.7. Consumers name the interface they
//! read through (`BufferInterface`); `buffer_slots` declares which slots
//! each emulated type provides. A new buffer type adds one arm there and
//! one in `buffer_contents`.

use crate::interp::builtins::containers::buffer_object::buffer_object;
use crate::interp::builtins::containers::memoryview;
use crate::interp::builtins::modules::array;
use crate::interp::builtins::modules::mmap;
use crate::interp::builtins::text::codecs::encode_default;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The interface through which a consumer reads a buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferInterface {
    /// `memoryview` and `_getbuffer`: the new buffer interface.
    New,
    /// `s*`: the new interface, or else an old read buffer.
    Any,
    /// `s#`, `z#`, and read-buffer consumers: an old read buffer whose
    /// type needs no release.
    Pinned,
    /// Character-buffer consumers: an old character buffer.
    Character,
    /// `t#`: a character buffer whose type needs no release.
    PinnedCharacter,
    /// `w#`: an old write buffer.
    Writable,
    /// `w*`: the new interface for writing, or else an old write buffer.
    /// A read-only `buffer` object fails the conversion without raising.
    WritableAny,
}

impl BufferInterface {
    /// The old buffer procedure the interface calls; `None` for
    /// the new interface.
    fn segment(self) -> Option<Segment> {
        match self {
            BufferInterface::New | BufferInterface::Any | BufferInterface::WritableAny => None,
            BufferInterface::Pinned => Some(Segment::Read),
            BufferInterface::Character | BufferInterface::PinnedCharacter => Some(Segment::Character),
            BufferInterface::Writable => Some(Segment::Write),
        }
    }
}

/// An old buffer procedure: read, write, or character segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Segment {
    Read,
    Write,
    Character,
}

/// The buffer interfaces a type provides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferSlots {
    pub new: bool,
    pub read: bool,
    pub write: bool,
    pub character: bool,
    pub release: bool,
}

impl BufferSlots {
    pub fn provides(self, interface: BufferInterface) -> bool {
        match interface {
            BufferInterface::New => self.new,
            BufferInterface::Any => self.new || self.read,
            BufferInterface::Pinned => self.read && !self.release,
            BufferInterface::Character => self.character,
            BufferInterface::PinnedCharacter => self.character && !self.release,
            BufferInterface::Writable | BufferInterface::WritableAny => self.write,
        }
    }

    fn has(self, segment: Segment) -> bool {
        match segment {
            Segment::Read => self.read,
            Segment::Write => self.write,
            Segment::Character => self.character,
        }
    }
}

impl Vm {
    /// The buffer slots of `value`'s type; `None` when it has none. Text
    /// is not included: its consumers convert it with the default encoding.
    pub fn buffer_slots(&self, value: &Value) -> Option<BufferSlots> {
        if self.as_str_bytes(value).is_some() {
            return Some(BufferSlots { new: true, read: true, write: false, character: true, release: false });
        }
        if let Some(Payload::ByteArray(_)) = value.as_object().map(|object| &object.payload) {
            return Some(BufferSlots { new: true, read: true, write: true, character: true, release: true });
        }
        if array::is_array(value) {
            return Some(BufferSlots { new: false, read: true, write: true, character: false, release: false });
        }
        if memoryview::is_memoryview(value) {
            return Some(BufferSlots { new: true, read: false, write: false, character: false, release: true });
        }
        if mmap::is_mmap(value) {
            return Some(BufferSlots { new: false, read: true, write: true, character: true, release: false });
        }
        if buffer_object(value).is_some() {
            return Some(BufferSlots { new: true, read: true, write: true, character: true, release: false });
        }

        None
    }

    /// The bytes `value` exposes through `interface`; `None` when its type
    /// does not provide that interface. Reading a buffer may fail;
    /// a character-buffer read reports a failing segment count as its own
    /// `TypeError`, and a `buffer` object raises when its base cannot supply
    /// the bytes.
    pub fn buffer(&self, value: &Value, interface: BufferInterface) -> PyResult<Option<PyBytes>> {
        // `w*` takes a memoryview through the new interface when it is writable.
        if interface == BufferInterface::WritableAny && memoryview::is_memoryview(value) {
            return Ok(memoryview::writable_buffer(value).and_then(|buffer| buffer.modify(|bytes| PyBytes::new(&*bytes))));
        }
        if !self.buffer_slots(value).is_some_and(|slots| slots.provides(interface)) {
            return Ok(None);
        }

        if let Some(object) = buffer_object(value) {
            if interface == BufferInterface::WritableAny && object.is_readonly() {
                return Ok(None);
            }
            let bytes = match interface.segment() {
                Some(segment) => object.segment(self, segment)?,
                None => object.contents(self)?,
            };
            return Ok(Some(bytes));
        }

        let writable = matches!(interface, BufferInterface::Writable | BufferInterface::WritableAny);
        match self.buffer_contents(value, writable) {
            Err(Signal::Raise(_)) if interface == BufferInterface::Character => Err(self.type_error("expected a single-segment buffer object")),
            contents => contents,
        }
    }

    /// `buffer` for consumers that check the segment count themselves and
    /// report a failing count as having no buffer, and for those that
    /// replace any raised error with their own, as `int()`, `long()`, and
    /// `float()` do.
    pub fn single_segment_buffer(&self, value: &Value, interface: BufferInterface) -> PyResult<Option<PyBytes>> {
        match self.buffer(value, interface) {
            Err(Signal::Raise(_)) => Ok(None),
            contents => contents,
        }
    }

    /// Whether `value`'s type has the old buffer procedure `segment`,
    /// including `unicode`, whose procedures read its code units.
    pub fn has_segment(&self, value: &Value, segment: Segment) -> bool {
        if self.as_text(value).is_some() {
            return true;
        }

        self.buffer_slots(value).is_some_and(|slots| slots.has(segment))
    }

    /// The bytes of `value`'s old buffer procedure `segment`; `None` when
    /// its type has none. `unicode` exposes its UCS-2 code units to reads
    /// and its default encoding to character reads.
    pub fn segment(&self, value: &Value, segment: Segment) -> PyResult<Option<PyBytes>> {
        if let Some(object) = buffer_object(value) {
            return object.segment(self, segment).map(Some);
        }
        if let Some(text) = self.as_text(value) {
            return match segment {
                Segment::Read => Ok(Some(PyBytes::new(text.units().iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>()))),
                Segment::Write => Err(self.type_error("cannot use unicode as modifiable buffer")),
                Segment::Character => encode_default(self, text.units()).map(Some),
            };
        }
        if !self.buffer_slots(value).is_some_and(|slots| slots.has(segment)) {
            return Ok(None);
        }

        self.buffer_contents(value, segment == Segment::Write)
    }

    /// Runs `write` over the bytes of `value`'s write buffer; `None` when
    /// its type has none.
    pub fn write_buffer<R>(&self, value: &Value, write: impl FnOnce(&mut [u8]) -> R) -> PyResult<Option<R>> {
        if let Some(Payload::ByteArray(data)) = value.as_object().map(|object| &object.payload) {
            return Ok(Some(write(&mut data.borrow_mut().bytes)));
        }
        if mmap::is_mmap(value) {
            return mmap::write_buffer_bytes(self, value, write).transpose();
        }
        if let Some(object) = buffer_object(value) {
            let mut write = Some(write);
            let mut result = None;
            object.write(self, &mut |bytes| result = write.take().map(|write| write(bytes)))?;
            return Ok(result);
        }
        if memoryview::is_memoryview(value) {
            return Ok(memoryview::writable_buffer(value).and_then(|buffer| buffer.modify(write)));
        }

        Ok(array::write_array_bytes(value, write))
    }

    /// The bytes of any buffer `value` exposes; `writable` reads the write
    /// segment.
    fn buffer_contents(&self, value: &Value, writable: bool) -> PyResult<Option<PyBytes>> {
        if let Some(bytes) = self.as_str_bytes(value) {
            return Ok(Some(bytes));
        }
        if let Some(bytes) = self.as_bytearray(value) {
            return Ok(Some(PyBytes::new(bytes)));
        }
        if let Some(contents) = mmap::buffer_bytes(self, value, writable) {
            return contents.map(Some);
        }

        Ok(array::array_bytes(value).or_else(|| memoryview::view_contents(value)).map(PyBytes::new))
    }
}
