//! The parser object: configuration, the input buffer, position tracking and
//! the parse entry points that drive the prolog and content processors.

use std::cell::RefCell;
use std::mem;
use std::rc::Rc;

use super::CallbackId;
use super::Callbacks;
use super::EntityContext;
use super::ErrorCode;
use super::HandlerSlot;
use super::ParamEntityParsing;
use super::Status;
use super::dtd::Dtd;
use super::encoding::ByteMap;
use super::encoding::Encoding;
use super::encoding::KnownEncoding;
use super::grammar::Grammar;

/// How much already parsed input the buffer keeps before the parse position.
const CONTEXT_BYTES: usize = 1024;

/// The smallest buffer allocation, before doubling.
const INITIAL_BUFFER: usize = 1024;

/// The namespace bound to the `xml` prefix in every namespace-aware parser.
pub(super) const XML_NAMESPACE: &[u8] = b"http://www.w3.org/XML/1998/namespace";

/// The namespace reserved for `xmlns` attributes.
pub(super) const XMLNS_NAMESPACE: &[u8] = b"http://www.w3.org/2000/xmlns/";

/// The life cycle of a parse.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Phase {
    Initialized,
    Parsing,
    Suspended,
    Finished,
}

/// What the next parse call does with the buffered input.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Stage {
    /// The encoding is not known yet.
    PrologStart,
    Prolog,
    Content,
    CdataSection,
    Epilog,
    /// Inside an ignored conditional section of an external subset.
    IgnoreSection,
    /// An external parsed entity in content, before its encoding is set up.
    ExternalEntityStart,
    /// An external parsed entity in content, before a byte order mark.
    ExternalEntityBom,
    /// An external parsed entity in content, before its text declaration.
    ExternalEntityDecl,
    /// An external parsed entity in content.
    ExternalEntityContent,
    /// An external parameter entity or subset, before its encoding is set up.
    ExternalParamStart,
    /// An external parameter entity or subset, at its first token.
    ExternalParamToken,
    /// An external parameter entity read for an entity value, before its text declaration.
    EntityValueStart,
    /// An external parameter entity read for an entity value.
    EntityValue,
    /// Parsing failed; every later call reports the same error.
    Failed,
}

/// A namespace binding of a prefix, or of the default namespace when `prefix` is `None`.
#[derive(Clone, Debug)]
pub(super) struct Binding {
    pub prefix: Option<Rc<[u8]>>,
    /// `None` undeclares the default namespace.
    pub uri: Option<Rc<[u8]>>,
}

/// An open element.
#[derive(Clone, Debug)]
pub(super) struct OpenTag {
    /// The name as written, in the encoding of its entity.
    pub raw_name: Vec<u8>,
    /// The name reported to the handlers.
    pub name: Rc<[u8]>,
    /// The number of bindings the start tag pushed.
    pub bindings: usize,
}

/// A position in the input: lines and columns counted from zero.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Position {
    pub line: u32,
    pub column: u32,
}

/// The parser.
pub struct Parser {
    pub(super) handlers: [Option<CallbackId>; HandlerSlot::COUNT],
    /// Internal entities are expanded even while a default handler is installed.
    pub(super) default_expand: bool,
    /// The namespace separator; `None` without namespace processing.
    pub(super) ns_separator: Option<u8>,
    pub(super) ns_triplets: bool,
    pub(super) param_entity_parsing: ParamEntityParsing,
    pub(super) use_foreign_dtd: bool,
    pub(super) base: Option<Rc<[u8]>>,
    /// The encoding the application named when creating the parser.
    pub(super) protocol_encoding: Option<Vec<u8>>,

    /// The input buffer: retained context, parsed and unparsed bytes.
    pub(super) data: Vec<u8>,
    /// The size the buffer would have; growing it discards stale pointers.
    capacity: usize,
    allocated: bool,
    /// Bytes handed out by `buffer` and not yet parsed.
    spare: Vec<u8>,
    /// Start of the unparsed bytes.
    pub(super) ptr: usize,
    /// End of the data the current parse call covers.
    pub(super) parse_end: usize,
    /// Bytes passed to the parser before `parse_end`.
    parse_end_index: i64,
    /// Start and end of the token being reported.
    pub(super) event: Option<usize>,
    pub(super) event_end: Option<usize>,
    /// `position` is the line and column at `position_ptr`.
    position_ptr: Option<usize>,
    position: Position,

    pub(super) phase: Phase,
    pub(super) final_buffer: bool,
    pub(super) error_code: ErrorCode,
    pub(super) stage: Stage,
    pub(super) encoding: Encoding,
    /// The encoding was settled by the protocol or the XML declaration.
    pub(super) encoding_fixed: bool,
    pub(super) dtd: Rc<RefCell<Dtd>>,
    pub(super) grammar: Grammar,

    /// Created for an external entity of another parser.
    pub(super) is_child: bool,
    /// Created for a parameter entity or the external subset.
    pub(super) is_param_entity: bool,
    /// An entity value is being read, so an external parameter entity parser
    /// created now reads replacement text.
    pub(super) in_entity_value: bool,

    pub(super) prolog: super::prolog::PrologState,
    pub(super) content: super::content::ContentState,
    /// Open general entities a child inherits from its context.
    pub(super) inherited_open: Vec<Rc<[u8]>>,
    pub(super) bindings: Vec<Binding>,
    /// The number of attributes the last start tag specified, times two.
    pub(super) specified_count: i32,
}

impl Parser {
    /// A parser for a document. `namespace_separator` turns on namespace
    /// processing; `Some(0)` joins names without a separator byte.
    pub fn new(encoding: Option<&[u8]>, namespace_separator: Option<u8>) -> Parser {
        let mut parser = Self::create(encoding, namespace_separator, Rc::new(RefCell::new(Dtd::new())));
        if namespace_separator.is_some() {
            parser.bindings.push(Binding { prefix: Some(Rc::from(&b"xml"[..])), uri: Some(Rc::from(XML_NAMESPACE)) });
        }

        parser
    }

    /// A stand-in that occupies the place of a parser lent elsewhere; it is never parsed with.
    pub fn placeholder() -> Parser {
        Self::create(None, None, Rc::new(RefCell::new(Dtd::new())))
    }

    fn create(encoding: Option<&[u8]>, ns_separator: Option<u8>, dtd: Rc<RefCell<Dtd>>) -> Parser {
        Parser {
            handlers: [None; HandlerSlot::COUNT],
            default_expand: true,
            ns_separator,
            ns_triplets: false,
            param_entity_parsing: ParamEntityParsing::Never,
            use_foreign_dtd: false,
            base: None,
            protocol_encoding: encoding.map(<[u8]>::to_vec),

            data: Vec::new(),
            capacity: 0,
            allocated: false,
            spare: Vec::new(),
            ptr: 0,
            parse_end: 0,
            parse_end_index: 0,
            event: None,
            event_end: None,
            position_ptr: None,
            position: Position::default(),

            phase: Phase::Initialized,
            final_buffer: false,
            error_code: ErrorCode::None,
            stage: Stage::PrologStart,
            encoding: Encoding::Utf8,
            encoding_fixed: false,
            dtd,
            grammar: Grammar::new(),

            is_child: false,
            is_param_entity: false,
            in_entity_value: false,

            prolog: super::prolog::PrologState::default(),
            content: super::content::ContentState::default(),
            inherited_open: Vec::new(),
            bindings: Vec::new(),
            specified_count: -1,
        }
    }

    /// Installs or removes a handler. Installing or removing the default
    /// handler this way turns off expansion of internal entities in content.
    pub fn set_handler(&mut self, slot: HandlerSlot, callback: Option<CallbackId>) {
        self.handlers[slot as usize] = callback;
        if slot == HandlerSlot::Default {
            self.default_expand = false;
        }
    }

    /// Installs or removes the default handler, keeping internal entities expanded.
    pub fn set_default_handler_expand(&mut self, callback: Option<CallbackId>) {
        self.handlers[HandlerSlot::Default as usize] = callback;
        self.default_expand = true;
    }

    pub fn handler(&self, slot: HandlerSlot) -> Option<CallbackId> {
        self.handlers[slot as usize]
    }

    pub(super) fn has(&self, slot: HandlerSlot) -> bool {
        self.handlers[slot as usize].is_some()
    }

    /// Checks the parse phase on entry to a parse call; `Some` ends the call.
    fn enter(&mut self) -> Option<Status> {
        match self.phase {
            Phase::Suspended => {
                self.error_code = ErrorCode::Suspended;
                Some(Status::Error)
            }
            Phase::Finished => {
                self.error_code = ErrorCode::Finished;
                Some(Status::Error)
            }
            Phase::Initialized | Phase::Parsing => {
                self.phase = Phase::Parsing;
                None
            }
        }
    }

    /// Parses `data`; `is_final` marks the end of the document.
    pub fn parse(&mut self, callbacks: &mut dyn Callbacks, data: &[u8], is_final: bool) -> Status {
        if let Some(status) = self.enter() {
            return status;
        }

        if data.is_empty() {
            self.final_buffer = is_final;
            if !is_final {
                return Status::Ok;
            }

            self.position_ptr = Some(self.ptr);
            self.parse_end = self.data.len();
            let start = self.ptr;
            let outcome = self.process(callbacks, start);
            // Without a buffer the parse ran over a null pointer, which
            // leaves no event position.
            if !self.allocated {
                self.event = None;
                self.event_end = None;
            }
            return match outcome {
                Ok(()) => match self.succeed() {
                    Phase::Suspended => {
                        self.advance_position(self.ptr);
                        Status::Suspended
                    }
                    Phase::Initialized | Phase::Parsing => {
                        self.phase = Phase::Finished;
                        Status::Ok
                    }
                    Phase::Finished => Status::Ok,
                },
                Err(code) => self.fail(code),
            };
        }

        let Some(target) = self.buffer(data.len()) else {
            return Status::Error;
        };
        target.copy_from_slice(data);

        self.parse_buffer(callbacks, data.len(), is_final)
    }

    /// A buffer of `len` bytes to fill before calling `parse_buffer`; `None`
    /// when the parser cannot take more input, with the error code set.
    pub fn buffer(&mut self, len: usize) -> Option<&mut [u8]> {
        match self.phase {
            Phase::Suspended => {
                self.error_code = ErrorCode::Suspended;
                return None;
            }
            Phase::Finished => {
                self.error_code = ErrorCode::Finished;
                return None;
            }
            Phase::Initialized | Phase::Parsing => {}
        }
        if i32::try_from(len).is_err() {
            self.error_code = ErrorCode::NoMemory;
            return None;
        }

        if len > self.capacity - self.data.len() {
            self.make_room(len);
        }
        if !self.allocated {
            return None;
        }

        self.spare.clear();
        self.spare.resize(len, 0);

        Some(&mut self.spare)
    }

    /// Frees space for `len` more bytes: moves the unparsed data and its
    /// retained context to the front, or grows the buffer. Growing invalidates
    /// the event and position pointers.
    fn make_room(&mut self, len: usize) {
        let keep = self.ptr.min(CONTEXT_BYTES);
        let needed = len + (self.data.len() - self.ptr) + keep;
        if needed <= self.capacity {
            if keep < self.ptr {
                let offset = self.ptr - keep;
                self.data.drain(..offset);
                self.ptr -= offset;
            }
            self.event = None;
            self.event_end = None;
            self.position_ptr = None;
            return;
        }

        let mut size = self.capacity - self.ptr;
        if size == 0 {
            size = INITIAL_BUFFER;
        }
        loop {
            size *= 2;
            if size >= needed {
                break;
            }
        }

        if self.allocated {
            self.data.drain(..self.ptr - keep);
            self.ptr = keep;
        } else {
            self.data.clear();
            self.ptr = 0;
        }
        self.capacity = size;
        self.allocated = true;
        self.event = None;
        self.event_end = None;
        self.position_ptr = None;
    }

    /// Parses `len` bytes written into the buffer from `buffer`.
    pub fn parse_buffer(&mut self, callbacks: &mut dyn Callbacks, len: usize, is_final: bool) -> Status {
        if let Some(status) = self.enter() {
            return status;
        }

        let start = self.ptr;
        self.position_ptr = Some(start);
        let len = len.min(self.spare.len());
        let spare = mem::take(&mut self.spare);
        self.data.extend_from_slice(&spare[..len]);
        self.spare = spare;
        self.parse_end = self.data.len();
        self.parse_end_index += len as i64;
        self.final_buffer = is_final;

        if let Err(code) = self.process(callbacks, start) {
            return self.fail(code);
        }
        self.succeed();

        let status = match self.phase {
            Phase::Suspended => Status::Suspended,
            Phase::Initialized | Phase::Parsing if is_final => {
                self.phase = Phase::Finished;
                return Status::Ok;
            }
            _ => Status::Ok,
        };
        self.advance_position(self.ptr);

        status
    }

    /// Records a processor run without error; returns the phase.
    fn succeed(&mut self) -> Phase {
        self.error_code = ErrorCode::None;

        self.phase
    }

    fn fail(&mut self, code: ErrorCode) -> Status {
        self.error_code = code;
        self.event_end = self.event;
        self.stage = Stage::Failed;

        Status::Error
    }

    /// Stops parsing from inside a handler. A resumable stop suspends; the
    /// rest of the input is never parsed, as resuming is not supported.
    pub fn stop(&mut self, resumable: bool) -> Status {
        match self.phase {
            Phase::Suspended => {
                if resumable {
                    self.error_code = ErrorCode::Suspended;
                    return Status::Error;
                }
                self.phase = Phase::Finished;
            }
            Phase::Finished => {
                self.error_code = ErrorCode::Finished;
                return Status::Error;
            }
            Phase::Initialized | Phase::Parsing => {
                if resumable {
                    if self.is_param_entity {
                        self.error_code = ErrorCode::SuspendPe;
                        return Status::Error;
                    }
                    self.phase = Phase::Suspended;
                } else {
                    self.phase = Phase::Finished;
                }
            }
        }

        Status::Ok
    }

    pub fn error_code(&self) -> ErrorCode {
        self.error_code
    }

    /// Brings `position` up to `target` when it lies ahead.
    fn sync_position(&mut self, target: usize) {
        let Some(from) = self.position_ptr else {
            return;
        };
        if target < from {
            return;
        }

        self.count_lines(from, target);
        self.position_ptr = Some(target);
    }

    /// Moves `position` to `target` unconditionally, as after a parse call.
    fn advance_position(&mut self, target: usize) {
        if let Some(from) = self.position_ptr {
            self.count_lines(from, target);
        }
        self.position_ptr = Some(target);
    }

    fn count_lines(&mut self, from: usize, to: usize) {
        let unit = self.encoding.unit();
        let mut pos = from;
        while pos < to {
            let code = self.encoding.raw_unit(&self.data, pos);
            if code == u32::from(b'\r') {
                self.position.line = self.position.line.wrapping_add(1);
                self.position.column = 0;
                pos += unit;
                if pos < to && self.encoding.raw_unit(&self.data, pos) == u32::from(b'\n') {
                    pos += unit;
                }
                continue;
            }
            if code == u32::from(b'\n') {
                self.position.line = self.position.line.wrapping_add(1);
                self.position.column = 0;
                pos += unit;
                continue;
            }

            self.position.column = self.position.column.wrapping_add(1);
            pos += self.encoding.step(&self.data, pos);
        }
    }

    /// The line of the current event, counted from one.
    pub fn current_line_number(&mut self) -> u32 {
        if let Some(event) = self.event {
            self.sync_position(event);
        }

        self.position.line.wrapping_add(1)
    }

    /// The column of the current event, counted from zero.
    pub fn current_column_number(&mut self) -> u32 {
        if let Some(event) = self.event {
            self.sync_position(event);
        }

        self.position.column
    }

    /// The byte offset of the current event in the input; -1 without one.
    pub fn current_byte_index(&self) -> i32 {
        let Some(event) = self.event else {
            return -1;
        };

        (self.parse_end_index - (self.parse_end as i64 - event as i64)) as i32
    }

    /// The input from the current event to the end of the buffered data.
    pub fn input_context(&self) -> Option<&[u8]> {
        let event = self.event?;
        if !self.allocated {
            return None;
        }

        Some(self.data.get(event..).unwrap_or_default())
    }

    pub fn set_base(&mut self, base: Option<&[u8]>) {
        self.base = base.map(Rc::from);
    }

    pub fn base(&self) -> Option<&[u8]> {
        self.base.as_deref()
    }

    fn is_running(&self) -> bool {
        matches!(self.phase, Phase::Parsing | Phase::Suspended)
    }

    /// Adds the prefix to expanded names that had one.
    pub fn set_return_ns_triplet(&mut self, enabled: bool) {
        if self.is_running() {
            return;
        }

        self.ns_triplets = enabled;
    }

    /// False once parsing has begun.
    pub fn set_param_entity_parsing(&mut self, parsing: ParamEntityParsing) -> bool {
        if self.is_running() {
            return false;
        }

        self.param_entity_parsing = parsing;
        true
    }

    /// Reads an external subset through the external entity handler even when
    /// the document declares none.
    pub fn use_foreign_dtd(&mut self, enabled: bool) -> ErrorCode {
        if self.is_running() {
            return ErrorCode::CantChangeFeatureOnceParsing;
        }

        self.use_foreign_dtd = enabled;
        ErrorCode::None
    }

    /// The number of attribute names and values the last start tag specified
    /// itself, before defaults; -1 before any start tag.
    pub fn specified_attribute_count(&self) -> i32 {
        self.specified_count
    }

    /// A parser for an external entity referenced by this one. `context` comes
    /// from the external entity handler: `None` for parameter entities.
    pub fn external_entity_parser(&mut self, context: Option<&[u8]>, encoding: Option<&[u8]>) -> Option<Parser> {
        let mut child = Self::create(encoding, self.ns_separator, Rc::clone(&self.dtd));
        child.handlers = self.handlers;
        child.default_expand = self.default_expand;
        child.ns_triplets = self.ns_triplets;
        child.param_entity_parsing = self.param_entity_parsing;
        child.is_child = true;
        child.in_entity_value = self.in_entity_value;

        match context {
            Some(context) => {
                if !child.apply_context(context) {
                    return None;
                }
                child.stage = Stage::ExternalEntityStart;
            }
            None => {
                child.is_param_entity = true;
                child.grammar = Grammar::new_external();
                child.stage = Stage::ExternalParamStart;
            }
        }

        Some(child)
    }

    /// Sets up the bindings and open entities a context string names.
    fn apply_context(&mut self, context: &[u8]) -> bool {
        for item in context.split(|&byte| byte == 0x0C) {
            let Some(equals) = item.iter().position(|&byte| byte == b'=') else {
                if item.is_empty() {
                    continue;
                }
                let name: Rc<[u8]> = Rc::from(item);
                if self.dtd.borrow().general.contains_key(&name) {
                    self.inherited_open.push(name);
                }
                continue;
            };

            let (prefix, uri) = (&item[..equals], &item[equals + 1..]);
            let prefix = if prefix.is_empty() { None } else { Some(Rc::from(prefix)) };
            if self.ns_separator.is_none() && prefix.is_none() {
                continue;
            }
            // Only the default namespace may be undeclared.
            if uri.is_empty() && prefix.is_some() {
                return false;
            }
            let uri = if uri.is_empty() { None } else { Some(Rc::from(uri)) };
            self.bindings.push(Binding { prefix, uri });
        }

        true
    }

    /// The context string for an external entity reference made now: the
    /// default namespace, other bound prefixes and the open general entities.
    pub(super) fn context(&self) -> ContextText {
        let mut text = Vec::new();
        let mut first = true;
        let mut separate = |text: &mut Vec<u8>| {
            if !first {
                text.push(0x0C);
            }
            first = false;
        };

        let mut seen: Vec<Option<&[u8]>> = Vec::new();
        let mut prefixes = Vec::new();
        for binding in self.bindings.iter().rev() {
            let key = binding.prefix.as_deref();
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
            prefixes.push(binding);
        }

        if let Some(default) = prefixes.iter().find(|binding| binding.prefix.is_none())
            && let Some(uri) = &default.uri
        {
            separate(&mut text);
            text.push(b'=');
            text.extend_from_slice(uri);
        }

        let named: Vec<_> = prefixes.iter().filter(|binding| binding.prefix.is_some() && binding.uri.is_some()).collect();
        if named.len() > 1 {
            return ContextText::HostOrdered;
        }
        for binding in named {
            separate(&mut text);
            text.extend_from_slice(binding.prefix.as_deref().unwrap_or_default());
            text.push(b'=');
            text.extend_from_slice(binding.uri.as_deref().unwrap_or_default());
        }

        let dtd = self.dtd.borrow();
        let mut open: Vec<&[u8]> = dtd.general.iter().filter(|(_, entity)| entity.open).map(|(name, _)| &**name).collect();
        for name in &self.inherited_open {
            if !open.contains(&&**name) {
                open.push(name);
            }
        }
        if open.len() > 1 {
            return ContextText::HostOrdered;
        }
        for name in open {
            separate(&mut text);
            text.extend_from_slice(name);
        }

        ContextText::Text(text)
    }

    /// Runs the processor for the current stage from `start`.
    fn process(&mut self, callbacks: &mut dyn Callbacks, start: usize) -> Result<(), ErrorCode> {
        match self.stage {
            Stage::Failed => Err(self.error_code),
            Stage::PrologStart => self.run_prolog_start(callbacks, start),
            Stage::Prolog => self.run_prolog(callbacks, start),
            Stage::Content => self.run_content(callbacks, start),
            Stage::CdataSection => self.run_cdata_section(callbacks, start),
            Stage::Epilog => self.run_epilog(callbacks, start),
            Stage::IgnoreSection => self.run_ignore_section(callbacks, start),
            Stage::ExternalEntityStart => self.run_external_entity_start(callbacks, start),
            Stage::ExternalEntityBom => self.run_external_entity_bom(callbacks, start),
            Stage::ExternalEntityDecl => self.run_external_entity_decl(callbacks, start),
            Stage::ExternalEntityContent => self.run_content(callbacks, start),
            Stage::ExternalParamStart => self.run_external_param_start(callbacks, start),
            Stage::ExternalParamToken => self.run_external_param_token(callbacks, start),
            Stage::EntityValueStart => self.run_entity_value_start(callbacks, start),
            Stage::EntityValue => self.run_entity_value(callbacks, start),
        }
    }

    /// Settles the encoding from the protocol name, before any input is read.
    /// Unknown names go to the unknown encoding handler.
    pub(super) fn init_protocol_encoding(&mut self, callbacks: &mut dyn Callbacks) -> Result<(), ErrorCode> {
        let Some(name) = self.protocol_encoding.clone() else {
            return Ok(());
        };
        if KnownEncoding::from_name(&name).is_some() {
            return Ok(());
        }

        match self.unknown_encoding(callbacks, &name) {
            Some(encoding) => {
                self.encoding = encoding;
                self.encoding_fixed = true;
                Ok(())
            }
            None => Err(ErrorCode::UnknownEncoding),
        }
    }

    /// Asks the unknown encoding handler about `name`.
    pub(super) fn unknown_encoding(&mut self, callbacks: &mut dyn Callbacks, name: &[u8]) -> Option<Encoding> {
        let callback = self.handler(HandlerSlot::UnknownEncoding)?;
        let map = callbacks.unknown_encoding(self, callback, name)?;
        let map = ByteMap::new(&map)?;

        Some(Encoding::Mapped(Box::new(map)))
    }

    /// The context argument for the external entity handler.
    pub(super) fn entity_context(context: &ContextText) -> EntityContext<'_> {
        match context {
            ContextText::Text(text) => EntityContext::Text(text),
            ContextText::HostOrdered => EntityContext::HostOrdered,
        }
    }
}

/// The context of an external entity reference.
pub(super) enum ContextText {
    Text(Vec<u8>),
    HostOrdered,
}
