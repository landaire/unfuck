//! `pyexpat`: the `xmlparser` type, which drives the expat port and
//! dispatches its callbacks to Python handlers.
//!
//! `xmlparser` implements attribute access through attribute hooks, so its
//! class exposes no descriptors: the hooks below compute every attribute.

use std::cell::Cell;
use std::cell::RefCell;
use std::mem;
use std::rc::Rc;

use num_traits::ToPrimitive;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::arguments::int_argument;
use crate::interp::builtins::arguments::long_argument;
use crate::interp::builtins::arguments::memory_error;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::codecs::args;
use crate::interp::builtins::modules::codecs::errors::Errors;
use crate::interp::builtins::modules::codecs::registry;
use crate::interp::builtins::modules::codecs::unicode;
use crate::interp::builtins::modules::expat::Attributes;
use crate::interp::builtins::modules::expat::CallbackId;
use crate::interp::builtins::modules::expat::Callbacks;
use crate::interp::builtins::modules::expat::ContentModel;
use crate::interp::builtins::modules::expat::EXPAT_VERSION_INFO;
use crate::interp::builtins::modules::expat::EntityContext;
use crate::interp::builtins::modules::expat::ErrorCode;
use crate::interp::builtins::modules::expat::HandlerSlot;
use crate::interp::builtins::modules::expat::ParamEntityParsing;
use crate::interp::builtins::modules::expat::Parser;
use crate::interp::builtins::modules::expat::Status;
use crate::interp::builtins::modules::expat::error_string;
use crate::interp::builtins::modules::expat::expat_version;
use crate::interp::builtins::modules::expat::feature_list;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::method_one_argument;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::sys::PY_VERSION;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::object::ModuleKind;
use crate::interp::object::ModuleState;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const TYPE_NAME: &str = "pyexpat.xmlparser";
const ERROR_KEY: &str = "pyexpat.ExpatError";

/// The default `buffer_size`.
const DEFAULT_BUFFER_SIZE: usize = 8192;

/// A no-op character data handler, installed after a character data handler
/// failed or was removed while a callback runs.
const NOOP_CHARACTER_DATA: CallbackId = CallbackId(64);
/// The external entity reference handler installed after a handler failed.
const ERROR_EXTERNAL_ENTITY_REF: CallbackId = CallbackId(65);
/// The handler for encodings expat does not know.
const UNKNOWN_ENCODING: CallbackId = CallbackId(66);

/// The parser's method table, which attribute lookup binds on access.
const METHODS: [MethodSpec; 8] = [
    method("Parse", parse),
    method("ParseFile", parse_file),
    method("SetBase", set_base),
    method("GetBase", get_base),
    method("ExternalEntityParserCreate", external_entity_parser_create),
    method("SetParamEntityParsing", set_param_entity_parsing),
    method("GetInputContext", get_input_context),
    method("UseForeignDTD", use_foreign_dtd),
];

/// The names `xmlparser.__getattr__` appends to `__members__` after the handlers.
const MEMBERS: [&str; 15] = [
    "ErrorCode",
    "ErrorLineNumber",
    "ErrorColumnNumber",
    "ErrorByteIndex",
    "CurrentLineNumber",
    "CurrentColumnNumber",
    "CurrentByteIndex",
    "buffer_size",
    "buffer_text",
    "buffer_used",
    "namespace_prefixes",
    "ordered_attributes",
    "returns_unicode",
    "specified_attributes",
    "intern",
];

/// The constants of `pyexpat.errors`, in module initialization order.
const ERROR_CONSTANTS: [(&str, i32); 37] = [
    ("XML_ERROR_NO_MEMORY", 1),
    ("XML_ERROR_SYNTAX", 2),
    ("XML_ERROR_NO_ELEMENTS", 3),
    ("XML_ERROR_INVALID_TOKEN", 4),
    ("XML_ERROR_UNCLOSED_TOKEN", 5),
    ("XML_ERROR_PARTIAL_CHAR", 6),
    ("XML_ERROR_TAG_MISMATCH", 7),
    ("XML_ERROR_DUPLICATE_ATTRIBUTE", 8),
    ("XML_ERROR_JUNK_AFTER_DOC_ELEMENT", 9),
    ("XML_ERROR_PARAM_ENTITY_REF", 10),
    ("XML_ERROR_UNDEFINED_ENTITY", 11),
    ("XML_ERROR_RECURSIVE_ENTITY_REF", 12),
    ("XML_ERROR_ASYNC_ENTITY", 13),
    ("XML_ERROR_BAD_CHAR_REF", 14),
    ("XML_ERROR_BINARY_ENTITY_REF", 15),
    ("XML_ERROR_ATTRIBUTE_EXTERNAL_ENTITY_REF", 16),
    ("XML_ERROR_MISPLACED_XML_PI", 17),
    ("XML_ERROR_UNKNOWN_ENCODING", 18),
    ("XML_ERROR_INCORRECT_ENCODING", 19),
    ("XML_ERROR_UNCLOSED_CDATA_SECTION", 20),
    ("XML_ERROR_EXTERNAL_ENTITY_HANDLING", 21),
    ("XML_ERROR_NOT_STANDALONE", 22),
    ("XML_ERROR_UNEXPECTED_STATE", 23),
    ("XML_ERROR_ENTITY_DECLARED_IN_PE", 24),
    ("XML_ERROR_FEATURE_REQUIRES_XML_DTD", 25),
    ("XML_ERROR_CANT_CHANGE_FEATURE_ONCE_PARSING", 26),
    ("XML_ERROR_UNBOUND_PREFIX", 27),
    ("XML_ERROR_UNDECLARING_PREFIX", 28),
    ("XML_ERROR_INCOMPLETE_PE", 29),
    ("XML_ERROR_XML_DECL", 30),
    ("XML_ERROR_TEXT_DECL", 31),
    ("XML_ERROR_PUBLICID", 32),
    ("XML_ERROR_SUSPENDED", 33),
    ("XML_ERROR_NOT_SUSPENDED", 34),
    ("XML_ERROR_ABORTED", 35),
    ("XML_ERROR_FINISHED", 36),
    ("XML_ERROR_SUSPEND_PE", 37),
];

/// The constants of `pyexpat.model`.
const MODEL_CONSTANTS: [(&str, i64); 10] = [
    ("XML_CTYPE_EMPTY", 1),
    ("XML_CTYPE_ANY", 2),
    ("XML_CTYPE_MIXED", 3),
    ("XML_CTYPE_NAME", 4),
    ("XML_CTYPE_CHOICE", 5),
    ("XML_CTYPE_SEQ", 6),
    ("XML_CQUANT_NONE", 0),
    ("XML_CQUANT_OPT", 1),
    ("XML_CQUANT_REP", 2),
    ("XML_CQUANT_PLUS", 3),
];

/// The Python handler slots, in their order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Handler {
    StartElement,
    EndElement,
    ProcessingInstruction,
    CharacterData,
    UnparsedEntityDecl,
    NotationDecl,
    StartNamespaceDecl,
    EndNamespaceDecl,
    Comment,
    StartCdataSection,
    EndCdataSection,
    Default,
    DefaultExpand,
    NotStandalone,
    ExternalEntityRef,
    StartDoctypeDecl,
    EndDoctypeDecl,
    EntityDecl,
    XmlDecl,
    ElementDecl,
    AttlistDecl,
    SkippedEntity,
}

const HANDLER_COUNT: usize = 22;

impl Handler {
    const ALL: [Handler; HANDLER_COUNT] = [
        Self::StartElement,
        Self::EndElement,
        Self::ProcessingInstruction,
        Self::CharacterData,
        Self::UnparsedEntityDecl,
        Self::NotationDecl,
        Self::StartNamespaceDecl,
        Self::EndNamespaceDecl,
        Self::Comment,
        Self::StartCdataSection,
        Self::EndCdataSection,
        Self::Default,
        Self::DefaultExpand,
        Self::NotStandalone,
        Self::ExternalEntityRef,
        Self::StartDoctypeDecl,
        Self::EndDoctypeDecl,
        Self::EntityDecl,
        Self::XmlDecl,
        Self::ElementDecl,
        Self::AttlistDecl,
        Self::SkippedEntity,
    ];

    fn index(self) -> usize {
        self as usize
    }

    fn name(self) -> &'static str {
        match self {
            Self::StartElement => "StartElementHandler",
            Self::EndElement => "EndElementHandler",
            Self::ProcessingInstruction => "ProcessingInstructionHandler",
            Self::CharacterData => "CharacterDataHandler",
            Self::UnparsedEntityDecl => "UnparsedEntityDeclHandler",
            Self::NotationDecl => "NotationDeclHandler",
            Self::StartNamespaceDecl => "StartNamespaceDeclHandler",
            Self::EndNamespaceDecl => "EndNamespaceDeclHandler",
            Self::Comment => "CommentHandler",
            Self::StartCdataSection => "StartCdataSectionHandler",
            Self::EndCdataSection => "EndCdataSectionHandler",
            Self::Default => "DefaultHandler",
            Self::DefaultExpand => "DefaultHandlerExpand",
            Self::NotStandalone => "NotStandaloneHandler",
            Self::ExternalEntityRef => "ExternalEntityRefHandler",
            Self::StartDoctypeDecl => "StartDoctypeDeclHandler",
            Self::EndDoctypeDecl => "EndDoctypeDeclHandler",
            Self::EntityDecl => "EntityDeclHandler",
            Self::XmlDecl => "XmlDeclHandler",
            Self::ElementDecl => "ElementDeclHandler",
            Self::AttlistDecl => "AttlistDeclHandler",
            Self::SkippedEntity => "SkippedEntityHandler",
        }
    }

    /// The handler slot for an attribute name.
    fn from_name(name: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|handler| handler.name().as_bytes() == name)
    }

    /// The callback expat hands back for the trampoline of this handler.
    fn callback(self) -> CallbackId {
        CallbackId(self as u16)
    }

    /// `handler_info[i].setter`: installs `callback` in the expat slot.
    fn install(self, parser: &mut Parser, callback: Option<CallbackId>) {
        let slot = match self {
            Self::StartElement => HandlerSlot::StartElement,
            Self::EndElement => HandlerSlot::EndElement,
            Self::ProcessingInstruction => HandlerSlot::ProcessingInstruction,
            Self::CharacterData => HandlerSlot::CharacterData,
            Self::UnparsedEntityDecl => HandlerSlot::UnparsedEntityDecl,
            Self::NotationDecl => HandlerSlot::NotationDecl,
            Self::StartNamespaceDecl => HandlerSlot::StartNamespaceDecl,
            Self::EndNamespaceDecl => HandlerSlot::EndNamespaceDecl,
            Self::Comment => HandlerSlot::Comment,
            Self::StartCdataSection => HandlerSlot::StartCdataSection,
            Self::EndCdataSection => HandlerSlot::EndCdataSection,
            Self::Default => HandlerSlot::Default,
            Self::DefaultExpand => {
                parser.set_default_handler_expand(callback);
                return;
            }
            Self::NotStandalone => HandlerSlot::NotStandalone,
            Self::ExternalEntityRef => HandlerSlot::ExternalEntityRef,
            Self::StartDoctypeDecl => HandlerSlot::StartDoctypeDecl,
            Self::EndDoctypeDecl => HandlerSlot::EndDoctypeDecl,
            Self::EntityDecl => HandlerSlot::EntityDecl,
            Self::XmlDecl => HandlerSlot::XmlDecl,
            Self::ElementDecl => HandlerSlot::ElementDecl,
            Self::AttlistDecl => HandlerSlot::AttlistDecl,
            Self::SkippedEntity => HandlerSlot::SkippedEntity,
        };

        parser.set_handler(slot, callback);
    }
}

/// A trampoline's `-1` return: with an exception set, or with
/// none (character data without a handler).
enum Failure {
    Raised(Signal),
    Silent,
}

/// An `xmlparser`.
struct XmlParser {
    /// The expat parser. A running parse holds the expat parser and leaves
    /// `Parser::placeholder()` here, except while a callback lends it back
    /// so that Python code can query and change it.
    parser: RefCell<Parser>,
    /// `Parse` or `ParseFile` is running. Expat does not support starting
    /// another parse on the same parser then.
    parsing: Cell<bool>,

    returns_unicode: Cell<bool>,
    ordered_attributes: Cell<bool>,
    specified_attributes: Cell<bool>,
    in_callback: Cell<bool>,
    ns_prefixes: Cell<bool>,

    /// `buffer`: the buffered character data, whose length is
    /// `buffer_used`; `None` while `buffer_text` is off.
    buffer: RefCell<Option<Vec<u8>>>,
    /// `buffer_size`, between 1 and `INT_MAX`.
    buffer_size: Cell<usize>,

    /// The dict that interns names; `None` when interning is off.
    intern: Option<ObjectRef>,
    handlers: RefCell<[Option<Value>; HANDLER_COUNT]>,
    /// The exception a callback left pending during a parse, for `Parse` to
    /// raise.
    pending: RefCell<Option<Signal>>,
}

impl_native_data!(XmlParser, "pyexpat.xmlparser");

impl XmlParser {
    fn new(parser: Parser, intern: Option<ObjectRef>) -> Self {
        Self {
            parser: RefCell::new(parser),
            parsing: Cell::new(false),
            returns_unicode: Cell::new(true),
            ordered_attributes: Cell::new(false),
            specified_attributes: Cell::new(false),
            in_callback: Cell::new(false),
            ns_prefixes: Cell::new(false),
            buffer: RefCell::new(None),
            buffer_size: Cell::new(DEFAULT_BUFFER_SIZE),
            intern,
            handlers: RefCell::new(Default::default()),
            pending: RefCell::new(None),
        }
    }

    fn handler(&self, handler: Handler) -> Option<Value> {
        self.handlers.borrow().get(handler.index()).cloned().flatten()
    }

    /// Whether a Python handler is set.
    fn has_handler(&self, handler: Handler) -> bool {
        self.handlers.borrow().get(handler.index()).is_some_and(Option::is_some)
    }

    fn store_handler(&self, handler: Handler, value: Option<Value>) -> Option<Value> {
        let mut handlers = self.handlers.borrow_mut();
        let slot = handlers.get_mut(handler.index())?;

        mem::replace(slot, value)
    }

    fn install(&self, handler: Handler, callback: Option<CallbackId>) {
        handler.install(&mut self.parser.borrow_mut(), callback);
    }

    fn buffer_used(&self) -> usize {
        self.buffer.borrow().as_ref().map_or(0, Vec::len)
    }

    fn set_pending(&self, signal: Signal) {
        *self.pending.borrow_mut() = Some(signal);
    }

    /// Leaves the exception of a failed trampoline pending.
    fn absorb(&self, failure: Failure) {
        if let Failure::Raised(signal) = failure {
            self.set_pending(signal);
        }
    }

    /// `clear_handlers(self, 0)`.
    fn clear_handlers(&self) {
        let removed: Vec<Option<Value>> = Handler::ALL.into_iter().map(|handler| self.store_handler(handler, None)).collect();
        for handler in Handler::ALL {
            self.install(handler, None);
        }

        drop(removed);
    }

    /// Stops dispatching to Python after a handler failed.
    fn flag_error(&self) {
        self.clear_handlers();
        self.parser.borrow_mut().set_handler(HandlerSlot::ExternalEntityRef, Some(ERROR_EXTERNAL_ENTITY_REF));
    }

    /// A handler call with the `in_callback` bracket around it. A failed
    /// call stops the parser (`XML_StopParser`).
    fn call_handler(&self, vm: &Vm, handler: Handler, args: Vec<Value>) -> PyResult<Value> {
        let Some(function) = self.handler(handler) else {
            return Ok(Value::None);
        };

        self.in_callback.set(true);
        let result = vm.call(&function, CallArgs::new(args));
        self.in_callback.set(false);

        if result.is_err() {
            self.parser.borrow_mut().stop(false);
        }

        result
    }

    /// Text as `unicode` or UTF-8 `str`, per `returns_unicode`.
    fn text_value(&self, vm: &Vm, text: &[u8]) -> PyResult<Value> {
        if !self.returns_unicode.get() {
            return Ok(Value::Str(PyBytes::new(text)));
        }

        Ok(Value::Unicode(decode_utf8(vm, text)?))
    }

    /// A NUL-terminated string, or `None` for NULL.
    fn c_text_value(&self, vm: &Vm, text: Option<&[u8]>) -> PyResult<Value> {
        let Some(text) = text else {
            return Ok(Value::None);
        };

        self.text_value(vm, until_nul(text))
    }

    /// Interns a name. NULL converts to `None`, which is interned too.
    fn intern(&self, vm: &Vm, text: Option<&[u8]>) -> PyResult<Value> {
        let result = self.c_text_value(vm, text)?;
        let Some(dict) = &self.intern else {
            return Ok(result);
        };

        if let Some(existing) = vm.dict_get(dict, &result)? {
            return Ok(existing);
        }
        vm.dict_set(dict, result.clone(), result.clone())?;

        Ok(result)
    }

    /// Calls the character data handler. A failure disables the Python handlers and
    /// replaces the character data trampoline with a no-op.
    fn call_character_handler(&self, vm: &Vm, data: &[u8]) -> Result<(), Failure> {
        if !self.has_handler(Handler::CharacterData) {
            return Err(Failure::Silent);
        }

        let result = self.text_value(vm, data).and_then(|text| self.call_handler(vm, Handler::CharacterData, vec![text]));
        if let Err(signal) = result {
            self.flag_error();
            self.install(Handler::CharacterData, Some(NOOP_CHARACTER_DATA));
            return Err(Failure::Raised(signal));
        }

        Ok(())
    }

    /// Flushes the character data buffer. The handler sees the buffer still full;
    /// it empties afterwards whatever the outcome.
    fn flush(&self, vm: &Vm) -> Result<(), Failure> {
        let data = match self.buffer.borrow().as_ref() {
            Some(buffer) if !buffer.is_empty() => buffer.clone(),
            _ => return Ok(()),
        };

        let result = self.call_character_handler(vm, &data);
        if let Some(buffer) = self.buffer.borrow_mut().as_mut() {
            buffer.clear();
        }

        result
    }

    /// The character data callback.
    fn character_data(&self, vm: &Vm, data: &[u8]) {
        if self.buffer.borrow().is_none() {
            if let Err(failure) = self.call_character_handler(vm, data) {
                self.absorb(failure);
            }
            return;
        }

        let size = self.buffer_size.get();
        if self.buffer_used().saturating_add(data.len()) > size {
            if let Err(failure) = self.flush(vm) {
                self.absorb(failure);
                return;
            }
            // The handler might have changed; the rest is dropped when
            // there is none anymore.
            if !self.has_handler(Handler::CharacterData) {
                return;
            }
        }

        if data.len() > size {
            let result = self.call_character_handler(vm, data);
            if let Some(buffer) = self.buffer.borrow_mut().as_mut() {
                buffer.clear();
            }
            if let Err(failure) = result {
                self.absorb(failure);
            }
            return;
        }

        // A handler that turned buffering off during the flush leaves no
        // buffer; C would write through a null pointer here.
        let appended = match self.buffer.borrow_mut().as_mut() {
            Some(buffer) => {
                buffer.extend_from_slice(data);
                true
            }
            None => false,
        };
        if !appended && let Err(failure) = self.call_character_handler(vm, data) {
            self.absorb(failure);
        }
    }

    /// Flushes buffered text, builds the arguments, and calls
    /// the Python handler. A failure leaves the exception pending and
    /// disables the handlers. `None` when no handler ran to completion.
    fn invoke(&self, vm: &Vm, handler: Handler, build: impl FnOnce() -> PyResult<Vec<Value>>) -> Option<Value> {
        if !self.has_handler(handler) {
            return None;
        }
        if let Err(failure) = self.flush(vm) {
            self.absorb(failure);
            return None;
        }

        let args = match build() {
            Ok(args) => args,
            Err(signal) => {
                self.set_pending(signal);
                self.flag_error();
                return None;
            }
        };

        match self.call_handler(vm, handler, args) {
            Ok(value) => Some(value),
            Err(signal) => {
                self.set_pending(signal);
                self.flag_error();
                None
            }
        }
    }

    /// The result as an `int` through C `long` conversion; a failed
    /// conversion yields -1 and leaves its exception pending.
    fn invoke_int(&self, vm: &Vm, handler: Handler, build: impl FnOnce() -> PyResult<Vec<Value>>) -> bool {
        let Some(result) = self.invoke(vm, handler, build) else {
            return false;
        };

        match int_as_long(vm, &result) {
            // C stores the `long` in an `int`.
            Ok(number) => number as i32 != 0,
            Err(signal) => {
                self.set_pending(signal);
                true
            }
        }
    }

    /// The start element callback.
    fn start_element(&self, vm: &Vm, name: &[u8], attributes: &Attributes<'_>) {
        if !self.has_handler(Handler::StartElement) {
            return;
        }
        if let Err(failure) = self.flush(vm) {
            self.absorb(failure);
            return;
        }

        // The specified count never goes negative.
        let count = if self.specified_attributes.get() { usize::try_from(self.parser.borrow().specified_attribute_count()).unwrap_or(0) } else { attributes.len() };
        let container = match self.attribute_container(vm, attributes, count) {
            Ok(container) => container,
            Err(signal) => {
                self.set_pending(signal);
                self.flag_error();
                return;
            }
        };

        // A name that fails to convert skips the handler without
        // disabling the others.
        let name = match self.intern(vm, Some(name)) {
            Ok(name) => name,
            Err(signal) => {
                self.set_pending(signal);
                return;
            }
        };

        if let Err(signal) = self.call_handler(vm, Handler::StartElement, vec![name, container]) {
            self.set_pending(signal);
            self.flag_error();
        }
    }

    /// The attributes as a dict, or a flat list with `ordered_attributes`.
    fn attribute_container(&self, vm: &Vm, attributes: &Attributes<'_>, count: usize) -> PyResult<Value> {
        let ordered = self.ordered_attributes.get();
        let dict = vm.new_dict();
        let mut items = Vec::new();

        for index in (0..count).step_by(2) {
            let (Some(name), Some(value)) = (attributes.get(index), attributes.get(index + 1)) else {
                break;
            };
            let name = self.intern(vm, Some(name))?;
            let value = self.c_text_value(vm, Some(value))?;
            if ordered {
                items.push(name);
                items.push(value);
            } else {
                vm.dict_set(&dict, name, value)?;
            }
        }

        if ordered {
            return Ok(vm.new_list(items));
        }

        Ok(Value::Object(dict))
    }

    /// The content model tuple, children first.
    fn content_model(&self, vm: &Vm, model: &ContentModel) -> PyResult<Value> {
        struct Pending<'m> {
            node: &'m ContentModel,
            children: Vec<Value>,
        }

        let mut stack = vec![Pending { node: model, children: Vec::with_capacity(model.children.len()) }];
        loop {
            let Some(top) = stack.last_mut() else {
                return Ok(Value::None);
            };
            let node = top.node;
            if let Some(child) = node.children.get(top.children.len()) {
                stack.push(Pending { node: child, children: Vec::with_capacity(child.children.len()) });
                continue;
            }

            let Some(done) = stack.pop() else {
                return Ok(Value::None);
            };
            let name = self.c_text_value(vm, done.node.name.as_deref())?;
            let value = Value::tuple(vec![Value::Int(i64::from(done.node.kind as i32)), Value::Int(i64::from(done.node.quant as i32)), name, Value::tuple(done.children)]);
            match stack.last_mut() {
                Some(parent) => parent.children.push(value),
                None => return Ok(value),
            }
        }
    }

    /// An `ExpatError` carrying the position of the error.
    fn error(&self, vm: &Vm, code: i32) -> Signal {
        let (line, column) = {
            let mut parser = self.parser.borrow_mut();
            (parser.current_line_number(), parser.current_column_number())
        };
        let line = c_long_from_size(line);
        let column = c_long_from_size(column);
        let message = format!("{}: line {line}, column {column}", error_string(code).unwrap_or("(null)"));

        let class = match native_type(vm, ERROR_KEY, create_error_class) {
            Ok(class) => class,
            Err(signal) => return signal,
        };
        let error = match vm.instantiate_exception(&class, vec![Value::str(&message)]) {
            Ok(error) => error,
            Err(signal) => return signal,
        };
        let attributes = [("code", i64::from(code)), ("offset", column), ("lineno", line)];
        for (name, value) in attributes {
            if let Err(signal) = vm.setattr_str(&error, name, Value::Int(value)) {
                return signal;
            }
        }

        Signal::Raise(error)
    }

    /// The result of `xmlparser.Parse`.
    fn parse_result(&self, vm: &Vm, status: Status) -> PyResult<Value> {
        let pending = self.pending.borrow_mut().take();
        if let Some(signal) = pending {
            return Err(signal);
        }
        if matches!(status, Status::Error) {
            let code = self.parser.borrow().error_code();
            return Err(self.error(vm, code as i32));
        }
        self.flush(vm).map_err(|failure| failure_signal(vm, failure))?;

        Ok(Value::Int(status as i64))
    }

    /// Runs `body` with the expat parser taken out of the object, so that
    /// callbacks can lend it back.
    fn with_taken_parser<R>(&self, vm: &Vm, body: impl FnOnce(&mut Parser, &mut Dispatch<'_>) -> R) -> R {
        let mut parser = mem::replace(&mut *self.parser.borrow_mut(), Parser::placeholder());
        let mut dispatch = Dispatch { vm, this: self };

        let result = body(&mut parser, &mut dispatch);
        *self.parser.borrow_mut() = parser;

        result
    }

    /// Runs expat through `body`, marked as parsing so that a callback
    /// cannot start another parse on the same parser.
    fn exclusive_parse<R>(&self, vm: &Vm, body: impl FnOnce(&mut Parser, &mut Dispatch<'_>) -> R) -> PyResult<R> {
        if self.parsing.get() {
            return Err(vm.halt_unsupported("xmlparser.Parse or ParseFile on a parser that is already parsing"));
        }

        self.parsing.set(true);
        let result = self.with_taken_parser(vm, body);
        self.parsing.set(false);

        Ok(result)
    }

    /// Stores a handler. Removing the character data handler during a callback
    /// installs the no-op trampoline, since expat may still call it.
    fn set_handler(&self, handler: Handler, value: Value) {
        let (stored, callback) = if value.is_none() {
            let callback = if handler == Handler::CharacterData && self.in_callback.get() { Some(NOOP_CHARACTER_DATA) } else { None };
            (None, callback)
        } else {
            (Some(value), Some(handler.callback()))
        };

        let previous = self.store_handler(handler, stored);
        self.install(handler, callback);

        drop(previous);
    }
}

/// The `Callbacks` of one parser object: each lends the expat parser back
/// to the object while it runs, then dispatches to the Python handler.
struct Dispatch<'a> {
    vm: &'a Vm,
    this: &'a XmlParser,
}

impl Dispatch<'_> {
    fn lend<R>(&self, parser: &mut Parser, body: impl FnOnce(&Vm, &XmlParser) -> R) -> R {
        mem::swap(&mut *self.this.parser.borrow_mut(), parser);
        let result = body(self.vm, self.this);
        mem::swap(&mut *self.this.parser.borrow_mut(), parser);

        result
    }
}

impl Callbacks for Dispatch<'_> {
    fn start_element(&mut self, parser: &mut Parser, _callback: CallbackId, name: &[u8], attributes: Attributes<'_>) {
        self.lend(parser, |vm, this| this.start_element(vm, name, &attributes));
    }

    fn end_element(&mut self, parser: &mut Parser, _callback: CallbackId, name: &[u8]) {
        self.lend(parser, |vm, this| {
            this.invoke(vm, Handler::EndElement, || Ok(vec![this.intern(vm, Some(name))?]));
        });
    }

    fn character_data(&mut self, parser: &mut Parser, callback: CallbackId, data: &[u8]) {
        if callback == NOOP_CHARACTER_DATA {
            return;
        }

        self.lend(parser, |vm, this| this.character_data(vm, data));
    }

    fn processing_instruction(&mut self, parser: &mut Parser, _callback: CallbackId, target: &[u8], data: &[u8]) {
        self.lend(parser, |vm, this| {
            this.invoke(vm, Handler::ProcessingInstruction, || Ok(vec![this.intern(vm, Some(target))?, this.c_text_value(vm, Some(data))?]));
        });
    }

    fn comment(&mut self, parser: &mut Parser, _callback: CallbackId, data: &[u8]) {
        self.lend(parser, |vm, this| {
            this.invoke(vm, Handler::Comment, || Ok(vec![this.c_text_value(vm, Some(data))?]));
        });
    }

    fn start_cdata_section(&mut self, parser: &mut Parser, _callback: CallbackId) {
        self.lend(parser, |vm, this| {
            this.invoke(vm, Handler::StartCdataSection, || Ok(Vec::new()));
        });
    }

    fn end_cdata_section(&mut self, parser: &mut Parser, _callback: CallbackId) {
        self.lend(parser, |vm, this| {
            this.invoke(vm, Handler::EndCdataSection, || Ok(Vec::new()));
        });
    }

    fn default(&mut self, parser: &mut Parser, callback: CallbackId, data: &[u8]) {
        let handler = if callback == Handler::DefaultExpand.callback() { Handler::DefaultExpand } else { Handler::Default };

        self.lend(parser, |vm, this| {
            this.invoke(vm, handler, || Ok(vec![this.text_value(vm, data)?]));
        });
    }

    fn start_doctype_decl(&mut self, parser: &mut Parser, _callback: CallbackId, name: Option<&[u8]>, system_id: Option<&[u8]>, public_id: Option<&[u8]>, has_internal_subset: bool) {
        self.lend(parser, |vm, this| {
            this.invoke(vm, Handler::StartDoctypeDecl, || Ok(vec![this.intern(vm, name)?, this.intern(vm, system_id)?, this.intern(vm, public_id)?, Value::Int(i64::from(has_internal_subset))]));
        });
    }

    fn end_doctype_decl(&mut self, parser: &mut Parser, _callback: CallbackId) {
        self.lend(parser, |vm, this| {
            this.invoke(vm, Handler::EndDoctypeDecl, || Ok(Vec::new()));
        });
    }

    fn entity_decl(&mut self, parser: &mut Parser, _callback: CallbackId, name: &[u8], is_parameter_entity: bool, value: Option<&[u8]>, base: Option<&[u8]>, system_id: Option<&[u8]>, public_id: Option<&[u8]>, notation_name: Option<&[u8]>) {
        self.lend(parser, |vm, this| {
            this.invoke(vm, Handler::EntityDecl, || {
                let value = match value {
                    Some(value) => this.text_value(vm, value)?,
                    None => Value::None,
                };
                Ok(vec![this.intern(vm, Some(name))?, Value::Int(i64::from(is_parameter_entity)), value, this.intern(vm, base)?, this.intern(vm, system_id)?, this.intern(vm, public_id)?, this.intern(vm, notation_name)?])
            });
        });
    }

    fn unparsed_entity_decl(&mut self, parser: &mut Parser, _callback: CallbackId, name: &[u8], base: Option<&[u8]>, system_id: &[u8], public_id: Option<&[u8]>, notation_name: &[u8]) {
        self.lend(parser, |vm, this| {
            this.invoke(vm, Handler::UnparsedEntityDecl, || Ok(vec![this.intern(vm, Some(name))?, this.intern(vm, base)?, this.intern(vm, Some(system_id))?, this.intern(vm, public_id)?, this.intern(vm, Some(notation_name))?]));
        });
    }

    fn notation_decl(&mut self, parser: &mut Parser, _callback: CallbackId, name: &[u8], base: Option<&[u8]>, system_id: Option<&[u8]>, public_id: Option<&[u8]>) {
        self.lend(parser, |vm, this| {
            this.invoke(vm, Handler::NotationDecl, || Ok(vec![this.intern(vm, Some(name))?, this.intern(vm, base)?, this.intern(vm, system_id)?, this.intern(vm, public_id)?]));
        });
    }

    fn start_namespace_decl(&mut self, parser: &mut Parser, _callback: CallbackId, prefix: Option<&[u8]>, uri: Option<&[u8]>) {
        self.lend(parser, |vm, this| {
            this.invoke(vm, Handler::StartNamespaceDecl, || Ok(vec![this.intern(vm, prefix)?, this.intern(vm, uri)?]));
        });
    }

    fn end_namespace_decl(&mut self, parser: &mut Parser, _callback: CallbackId, prefix: Option<&[u8]>) {
        self.lend(parser, |vm, this| {
            this.invoke(vm, Handler::EndNamespaceDecl, || Ok(vec![this.intern(vm, prefix)?]));
        });
    }

    fn not_standalone(&mut self, parser: &mut Parser, _callback: CallbackId) -> bool {
        self.lend(parser, |vm, this| this.invoke_int(vm, Handler::NotStandalone, || Ok(Vec::new())))
    }

    fn external_entity_ref(&mut self, parser: &mut Parser, callback: CallbackId, context: EntityContext<'_>, base: Option<&[u8]>, system_id: Option<&[u8]>, public_id: Option<&[u8]>) -> bool {
        if callback == ERROR_EXTERNAL_ENTITY_REF {
            return false;
        }

        self.lend(parser, |vm, this| {
            this.invoke_int(vm, Handler::ExternalEntityRef, || {
                let context = match context {
                    EntityContext::Absent => Value::None,
                    EntityContext::Text(text) => this.c_text_value(vm, Some(text))?,
                    EntityContext::HostOrdered => Value::unknown("pyexpat external entity context (hash order seeded by the host)"),
                };
                Ok(vec![context, this.intern(vm, base)?, this.intern(vm, system_id)?, this.intern(vm, public_id)?])
            })
        })
    }

    fn skipped_entity(&mut self, parser: &mut Parser, _callback: CallbackId, name: &[u8], is_parameter_entity: bool) {
        self.lend(parser, |vm, this| {
            this.invoke(vm, Handler::SkippedEntity, || Ok(vec![this.intern(vm, Some(name))?, Value::Int(i64::from(is_parameter_entity))]));
        });
    }

    fn unknown_encoding(&mut self, parser: &mut Parser, _callback: CallbackId, name: &[u8]) -> Option<[i32; 256]> {
        self.lend(parser, |vm, this| match unknown_encoding_map(vm, name) {
            Ok(map) => Some(map),
            Err(signal) => {
                this.set_pending(signal);
                None
            }
        })
    }

    fn xml_decl(&mut self, parser: &mut Parser, _callback: CallbackId, version: Option<&[u8]>, encoding: Option<&[u8]>, standalone: i32) {
        self.lend(parser, |vm, this| {
            this.invoke(vm, Handler::XmlDecl, || Ok(vec![this.c_text_value(vm, version)?, this.c_text_value(vm, encoding)?, Value::Int(i64::from(standalone))]));
        });
    }

    fn element_decl(&mut self, parser: &mut Parser, _callback: CallbackId, name: &[u8], model: ContentModel) {
        self.lend(parser, |vm, this| {
            this.invoke(vm, Handler::ElementDecl, || {
                let model = this.content_model(vm, &model)?;
                Ok(vec![this.intern(vm, Some(name))?, model])
            });
        });
    }

    fn attlist_decl(&mut self, parser: &mut Parser, _callback: CallbackId, element_name: &[u8], attribute_name: &[u8], attribute_type: &[u8], default: Option<&[u8]>, is_required: bool) {
        self.lend(parser, |vm, this| {
            this.invoke(vm, Handler::AttlistDecl, || {
                Ok(vec![this.intern(vm, Some(element_name))?, this.intern(vm, Some(attribute_name))?, this.c_text_value(vm, Some(attribute_type))?, this.c_text_value(vm, default)?, Value::Int(i64::from(is_required))])
            });
        });
    }
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    const FUNCTIONS: [MethodSpec; 2] = [
        function("ParserCreate", parser_create),
        function("ErrorString", error_string_function),
    ];

    install_functions(vm, module, &FUNCTIONS)?;

    let error = Value::Object(native_type(vm, ERROR_KEY, create_error_class)?);
    set_attribute(vm, module, "error", error.clone())?;
    set_attribute(vm, module, "ExpatError", error)?;
    set_attribute(vm, module, "XMLParserType", Value::Object(native_type(vm, TYPE_NAME, create_parser_type)?))?;

    set_attribute(vm, module, "__version__", Value::str(PY_VERSION))?;
    set_attribute(vm, module, "EXPAT_VERSION", Value::str(expat_version()))?;
    let (major, minor, micro) = EXPAT_VERSION_INFO;
    set_attribute(vm, module, "version_info", Value::tuple(vec![Value::Int(i64::from(major)), Value::Int(i64::from(minor)), Value::Int(i64::from(micro))]))?;
    set_attribute(vm, module, "native_encoding", Value::str("UTF-8"))?;

    let errors = submodule(vm, module, "errors")?;
    let model = submodule(vm, module, "model")?;

    let features = feature_list().iter().map(|(name, value)| Value::tuple(vec![Value::str(name), Value::Int(*value)])).collect();
    set_attribute(vm, module, "features", vm.new_list(features))?;

    for (name, code) in ERROR_CONSTANTS {
        set_attribute(vm, &errors, name, Value::str(error_string(code).unwrap_or_default()))?;
    }

    set_attribute(vm, module, "XML_PARAM_ENTITY_PARSING_NEVER", Value::Int(0))?;
    set_attribute(vm, module, "XML_PARAM_ENTITY_PARSING_UNLESS_STANDALONE", Value::Int(1))?;
    set_attribute(vm, module, "XML_PARAM_ENTITY_PARSING_ALWAYS", Value::Int(2))?;

    for (name, value) in MODEL_CONSTANTS {
        set_attribute(vm, &model, name, Value::Int(value))?;
    }

    // `pyexpat` is an extension module file whose location depends on the
    // installation.
    set_attribute(vm, module, "__file__", Value::unknown("pyexpat.__file__"))
}

/// `pyexpat.errors` or `pyexpat.model`, which `sys.modules` also holds.
fn submodule(vm: &Vm, module: &ObjectRef, name: &str) -> PyResult<ObjectRef> {
    let full_name = format!("pyexpat.{name}");
    let submodule = vm.new_module(&full_name, ModuleKind::Native)?;
    if let Some(data) = submodule.as_module() {
        data.state.set(ModuleState::Ready);
    }

    vm.dict_set(vm.modules(), Value::str(&full_name), Value::Object(Rc::clone(&submodule)))?;
    set_attribute(vm, module, name, Value::Object(Rc::clone(&submodule)))?;

    Ok(submodule)
}

/// The `xml.parsers.expat.ExpatError` exception class.
fn create_error_class(vm: &Vm) -> PyResult<ObjectRef> {
    let base = Rc::clone(vm.types().exception(ExceptionKind::Exception));

    new_exception_class(vm, "xml.parsers.expat", "ExpatError", &base)
}

fn create_parser_type(vm: &Vm) -> PyResult<ObjectRef> {
    const SLOTS: &[MethodSpec] = &[
        static_method("__new__", parser_new),
        method("__getattribute__", parser_getattr),
        method("__setattr__", parser_setattr),
        method("__delattr__", parser_delattr),
    ];

    let class = new_final_type(vm, TypeSpec { name: "xmlparser", module: "pyexpat", base: None, layout: Layout::Native, instance_dict: false, methods: SLOTS })?;
    if let Some(data) = class.as_class() {
        vm.dict_set(&data.dict, Value::str("__doc__"), Value::str("XML parser"))?;
    }

    Ok(class)
}

fn parser_new(vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    Err(vm.type_error("cannot create 'pyexpat.xmlparser' instances"))
}

/// A converted argument of `ParserCreate`.
enum CreateArgument {
    Text(Option<PyBytes>),
    Object(Value),
}

/// `ParserCreate(encoding=None, namespace_separator=None, intern=None)`.
fn parser_create(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let slots = parse_with(vm, args, "ParserCreate", &["encoding", "namespace_separator", "intern"], 0, |vm, index, value| {
        if value.is_unknown() {
            return Err(vm.halt_unsupported("pyexpat.ParserCreate with an unknown argument"));
        }
        if index == 2 {
            return Ok(CreateArgument::Object(value));
        }
        args::optional_string(vm, "ParserCreate", index + 1, Some(&value)).map(CreateArgument::Text)
    })?;
    let mut slots = slots.into_iter();
    let encoding = match slots.next().flatten() {
        Some(CreateArgument::Text(text)) => text,
        _ => None,
    };
    let separator = match slots.next().flatten() {
        Some(CreateArgument::Text(text)) => text,
        _ => None,
    };
    let intern = match slots.next().flatten() {
        Some(CreateArgument::Object(value)) => Some(value),
        _ => None,
    };

    if separator.as_ref().is_some_and(|separator| separator.as_bytes().len() > 1) {
        return Err(vm.raise(ExceptionKind::ValueError, "namespace_separator must be at most one character, omitted, or None"));
    }

    // An explicit None turns interning off; an absent argument means a
    // new dict.
    let intern = match intern {
        None => Some(vm.new_dict()),
        Some(Value::None) => None,
        Some(Value::Object(dict)) if dict.as_dict().is_some() => Some(dict),
        Some(_) => return Err(vm.type_error("intern must be a dictionary")),
    };

    let namespace_separator = separator.map(|separator| separator.as_bytes().first().copied().unwrap_or(0));
    let mut parser = Parser::new(encoding.as_ref().map(PyBytes::as_bytes), namespace_separator);
    parser.set_handler(HandlerSlot::UnknownEncoding, Some(UNKNOWN_ENCODING));

    new_parser_object(vm, XmlParser::new(parser, intern))
}

fn new_parser_object(vm: &Vm, parser: XmlParser) -> PyResult<Value> {
    let class = native_type(vm, TYPE_NAME, create_parser_type)?;

    Ok(new_native_object(vm, &class, parser))
}

/// `ErrorString(errno)`.
fn error_string_function(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let rest = varargs(vm, &args, 0, Some("ErrorString"), 1, 1)?;
    let Some(code) = rest.first() else {
        return Ok(Value::None);
    };
    let code = long_argument(vm, code)?;

    // C passes the `long` as an `int`.
    match error_string(code as i32) {
        Some(text) => Ok(Value::str(text)),
        None => Ok(Value::None),
    }
}

/// The argument checks of a varargs call whose first `receivers`
/// positional arguments are bound; `name` is the format's function name,
/// if it has one.
fn varargs(vm: &Vm, args: &CallArgs, receivers: usize, name: Option<&str>, minimum: usize, maximum: usize) -> PyResult<Vec<Value>> {
    let method_name = name.unwrap_or("function");
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{method_name}() takes no keyword arguments")));
    }

    let rest: Vec<Value> = args.positional.iter().skip(receivers).cloned().collect();
    let given = rest.len();
    if given < minimum || given > maximum {
        let (bound, count) = if minimum == maximum {
            ("exactly", minimum)
        } else if given < minimum {
            ("at least", minimum)
        } else {
            ("at most", maximum)
        };
        let plural = if count == 1 { "" } else { "s" };
        let shown = match name {
            Some(name) => format!("{name}()"),
            None => "function".to_owned(),
        };
        return Err(vm.type_error(&format!("{shown} takes {bound} {count} argument{plural} ({given} given)")));
    }

    Ok(rest)
}

/// `xmlparser.Parse(data[, isfinal])`.
fn parse(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let this = this::<XmlParser>(vm, &args, TYPE_NAME, "Parse")?;
    let rest = varargs(vm, &args, 1, Some("Parse"), 1, 2)?;
    if rest.iter().any(Value::is_unknown) {
        return Err(vm.halt_unsupported("xmlparser.Parse with unknown data"));
    }
    let Some(data) = rest.first() else {
        return Ok(Value::None);
    };
    let data = args::read_buffer(vm, "Parse", 1, data)?;
    let is_final = match rest.get(1) {
        Some(flag) => int_argument(vm, flag)? != 0,
        None => false,
    };

    let status = this.exclusive_parse(vm, |parser, dispatch| parser.parse(dispatch, data.as_bytes(), is_final))?;

    this.parse_result(vm, status)
}

/// `xmlparser.ParseFile`: feeds `file.read(2048)` results until one is
/// empty.
fn parse_file(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    const BUF_SIZE: usize = 2048;

    let this = this::<XmlParser>(vm, &args, TYPE_NAME, "ParseFile")?;
    let file = method_one_argument(vm, &args, "ParseFile")?;
    let read = match vm.getattr_opt(&file, &PyBytes::from("read")) {
        Ok(Some(read)) => read,
        Ok(None) | Err(Signal::Raise(_)) => return Err(vm.type_error("argument must have 'read' attribute")),
        Err(halt) => return Err(halt),
    };

    // Only expat runs exclusively: `read()` may parse with this parser, as
    // C allows.
    loop {
        if this.parser.borrow_mut().buffer(BUF_SIZE).is_none() {
            return this.parse_result(vm, Status::Error);
        }

        let data = read_chunk(vm, &read, BUF_SIZE)?;
        let length = data.len();
        let status = this.exclusive_parse(vm, |parser, dispatch| {
            let Some(buffer) = parser.buffer(BUF_SIZE) else {
                return Status::Error;
            };
            if let Some(target) = buffer.get_mut(..length) {
                target.copy_from_slice(&data);
            }
            parser.parse_buffer(dispatch, length, length == 0)
        })?;

        let pending = this.pending.borrow_mut().take();
        if let Some(signal) = pending {
            return Err(signal);
        }
        if matches!(status, Status::Error) || length == 0 {
            return this.parse_result(vm, status);
        }
    }
}

/// One `read(size)` call, which must return a `str` of at most
/// `size` bytes.
fn read_chunk(vm: &Vm, read: &Value, size: usize) -> PyResult<Vec<u8>> {
    let result = vm.call1(read, args::index_value(size))?;
    if result.is_unknown() {
        return Err(vm.halt_unsupported("xmlparser.ParseFile on a file whose read() result is unknown"));
    }
    let Some(bytes) = vm.as_str_bytes(&result) else {
        return Err(vm.type_error(&format!("read() did not return a string object (type={})", vm.type_name(&result))));
    };

    let length = bytes.as_bytes().len();
    if length > size {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("read() returned too much data: {size} bytes requested, {length} returned")));
    }

    Ok(bytes.as_bytes().to_vec())
}

/// `SetBase(base_url)`.
fn set_base(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let this = this::<XmlParser>(vm, &args, TYPE_NAME, "SetBase")?;
    let rest = varargs(vm, &args, 1, Some("SetBase"), 1, 1)?;
    let Some(base) = rest.first() else {
        return Ok(Value::None);
    };
    if base.is_unknown() {
        return Err(vm.halt_unsupported("xmlparser.SetBase with an unknown base"));
    }
    let base = args::c_string(vm, "SetBase", 1, base)?;

    this.parser.borrow_mut().set_base(Some(base.as_bytes()));

    Ok(Value::None)
}

/// `GetBase()`.
fn get_base(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let this = this::<XmlParser>(vm, &args, TYPE_NAME, "GetBase")?;
    method_no_arguments(vm, &args, "GetBase")?;

    let parser = this.parser.borrow();
    match parser.base() {
        Some(base) => Ok(Value::Str(PyBytes::new(base))),
        None => Ok(Value::None),
    }
}

/// `GetInputContext()`: the input text of the current event, only while
/// a handler runs.
fn get_input_context(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let this = this::<XmlParser>(vm, &args, TYPE_NAME, "GetInputContext")?;
    method_no_arguments(vm, &args, "GetInputContext")?;

    if !this.in_callback.get() {
        return Ok(Value::None);
    }

    let parser = this.parser.borrow();
    match parser.input_context() {
        Some(context) => Ok(Value::Str(PyBytes::new(context))),
        None => Ok(Value::None),
    }
}

/// `ExternalEntityParserCreate(context[, encoding])`: a parser for an
/// external entity, with this parser's handlers and settings.
fn external_entity_parser_create(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let this = this::<XmlParser>(vm, &args, TYPE_NAME, "ExternalEntityParserCreate")?;
    let rest = varargs(vm, &args, 1, Some("ExternalEntityParserCreate"), 1, 2)?;
    if rest.iter().any(Value::is_unknown) {
        return Err(vm.halt_unsupported("xmlparser.ExternalEntityParserCreate with an unknown argument"));
    }
    let context = args::optional_string(vm, "ExternalEntityParserCreate", 1, rest.first())?;
    let encoding = rest.get(1).map(|encoding| args::c_string(vm, "ExternalEntityParserCreate", 2, encoding)).transpose()?;

    let child = this.parser.borrow_mut().external_entity_parser(context.as_ref().map(PyBytes::as_bytes), encoding.as_ref().map(PyBytes::as_bytes));
    let Some(child) = child else {
        return Err(memory_error(vm));
    };

    let new = XmlParser::new(child, this.intern.clone());
    new.buffer_size.set(this.buffer_size.get());
    if this.buffer.borrow().is_some() {
        *new.buffer.borrow_mut() = Some(Vec::new());
    }
    new.returns_unicode.set(this.returns_unicode.get());
    new.ordered_attributes.set(this.ordered_attributes.get());
    new.specified_attributes.set(this.specified_attributes.get());
    new.ns_prefixes.set(this.ns_prefixes.get());

    for handler in Handler::ALL {
        if let Some(value) = this.handler(handler) {
            new.store_handler(handler, Some(value));
            new.install(handler, Some(handler.callback()));
        }
    }

    new_parser_object(vm, new)
}

/// `SetParamEntityParsing(flag)`, whose format names no function.
fn set_param_entity_parsing(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let this = this::<XmlParser>(vm, &args, TYPE_NAME, "SetParamEntityParsing")?;
    let rest = varargs(vm, &args, 1, None, 1, 1)?;
    let Some(flag) = rest.first() else {
        return Ok(Value::None);
    };
    let flag = int_argument(vm, flag)?;

    // Expat stores any value; only `NEVER` and `UNLESS_STANDALONE` are
    // compared against, so every other value parses as `ALWAYS`.
    let parsing = match flag {
        0 => ParamEntityParsing::Never,
        1 => ParamEntityParsing::UnlessStandalone,
        _ => ParamEntityParsing::Always,
    };
    let accepted = this.parser.borrow_mut().set_param_entity_parsing(parsing);

    Ok(Value::Int(i64::from(accepted)))
}

/// `UseForeignDTD([flag])`.
fn use_foreign_dtd(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let this = this::<XmlParser>(vm, &args, TYPE_NAME, "UseForeignDTD")?;
    let rest = varargs(vm, &args, 1, Some("UseForeignDTD"), 0, 1)?;
    let flag = match rest.first() {
        Some(flag) => vm.truthy(flag, "UseForeignDTD flag")?,
        None => true,
    };

    let code = this.parser.borrow_mut().use_foreign_dtd(flag);
    if !matches!(code, ErrorCode::None) {
        return Err(this.error(vm, code as i32));
    }

    Ok(Value::None)
}

/// Attribute lookup on a parser, including its methods.
fn parser_getattr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let this = this::<XmlParser>(vm, &args, TYPE_NAME, "__getattribute__")?;
    let rest = varargs(vm, &args, 1, Some("__getattribute__"), 1, 1)?;
    let (Some(receiver), Some(name)) = (args.positional.first(), rest.first()) else {
        return Ok(Value::None);
    };
    let Some(name) = vm.as_str_bytes(name) else {
        return Err(vm.type_error("attribute name must be string"));
    };

    if let Some(handler) = Handler::from_name(name.as_bytes()) {
        return Ok(this.handler(handler).unwrap_or(Value::None));
    }

    let value = match name.as_bytes() {
        b"ErrorCode" => Value::Int(i64::from(this.parser.borrow().error_code() as i32)),
        b"ErrorLineNumber" | b"CurrentLineNumber" => Value::Int(c_long_from_size(this.parser.borrow_mut().current_line_number())),
        b"ErrorColumnNumber" | b"CurrentColumnNumber" => Value::Int(c_long_from_size(this.parser.borrow_mut().current_column_number())),
        b"ErrorByteIndex" | b"CurrentByteIndex" => Value::Int(i64::from(this.parser.borrow().current_byte_index())),
        b"buffer_size" => args::index_value(this.buffer_size.get()),
        b"buffer_text" => Value::Bool(this.buffer.borrow().is_some()),
        b"buffer_used" => args::index_value(this.buffer_used()),
        b"namespace_prefixes" => Value::Bool(this.ns_prefixes.get()),
        b"ordered_attributes" => Value::Bool(this.ordered_attributes.get()),
        b"returns_unicode" => Value::Bool(this.returns_unicode.get()),
        b"specified_attributes" => Value::Bool(this.specified_attributes.get()),
        b"intern" => this.intern.as_ref().map_or(Value::None, |dict| Value::Object(Rc::clone(dict))),
        b"__members__" => {
            let names = Handler::ALL.into_iter().map(Handler::name).chain(MEMBERS).map(Value::str).collect();
            vm.new_list(names)
        }
        b"__methods__" => {
            let mut names: Vec<&str> = METHODS.iter().map(|spec| spec.name).collect();
            names.sort_unstable();
            vm.new_list(names.into_iter().map(Value::str).collect())
        }
        b"__doc__" => Value::str("XML parser"),
        other => {
            let Some(spec) = METHODS.iter().find(|spec| spec.name.as_bytes() == other) else {
                let class = Rc::clone(vm.types().exception(ExceptionKind::AttributeError));
                return Err(vm.raise_string(&class, Value::Str(name.clone())));
            };
            let owner = receiver.as_object().map(|object| object.class());
            vm.new_bound_native(spec.name, spec.function, receiver.clone(), owner)
        }
    };

    Ok(value)
}

/// `xmlparser.__setattr__` for an assignment.
fn parser_setattr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let this = this::<XmlParser>(vm, &args, TYPE_NAME, "__setattr__")?;
    let rest = varargs(vm, &args, 1, Some("__setattr__"), 2, 2)?;
    let (Some(name), Some(value)) = (rest.first(), rest.get(1)) else {
        return Ok(Value::None);
    };
    let Some(name) = vm.as_str_bytes(name) else {
        return Err(vm.type_error("attribute name must be string"));
    };

    match name.as_bytes() {
        b"buffer_text" => {
            if vm.truthy(value, "xmlparser.buffer_text")? {
                let mut buffer = this.buffer.borrow_mut();
                if buffer.is_none() {
                    *buffer = Some(Vec::new());
                }
            } else if this.buffer.borrow().is_some() {
                this.flush(vm).map_err(|failure| failure_signal(vm, failure))?;
                *this.buffer.borrow_mut() = None;
            }
        }
        b"namespace_prefixes" => {
            let flag = vm.truthy(value, "xmlparser.namespace_prefixes")?;
            this.ns_prefixes.set(flag);
            this.parser.borrow_mut().set_return_ns_triplet(flag);
        }
        b"ordered_attributes" => this.ordered_attributes.set(vm.truthy(value, "xmlparser.ordered_attributes")?),
        b"returns_unicode" => this.returns_unicode.set(vm.truthy(value, "xmlparser.returns_unicode")?),
        b"specified_attributes" => this.specified_attributes.set(vm.truthy(value, "xmlparser.specified_attributes")?),
        b"buffer_size" => set_buffer_size(vm, this, value)?,
        other => {
            let Some(handler) = Handler::from_name(other) else {
                let class = Rc::clone(vm.types().exception(ExceptionKind::AttributeError));
                return Err(vm.raise_string(&class, Value::Str(name.clone())));
            };
            if value.is_unknown() {
                return Err(vm.halt_unsupported("xmlparser handler set to an unknown value"));
            }
            // Text buffered for the old character data handler goes to it.
            if handler == Handler::CharacterData {
                this.flush(vm).map_err(|failure| failure_signal(vm, failure))?;
            }
            this.set_handler(handler, value.clone());
        }
    }

    Ok(Value::None)
}

/// The `buffer_size` assignment, which also turns buffering on.
fn set_buffer_size(vm: &Vm, this: &XmlParser, value: &Value) -> PyResult<()> {
    if value.is_unknown() {
        return Err(vm.halt_unsupported("xmlparser.buffer_size set to an unknown value"));
    }
    let Some(size) = args::plain_int(value).filter(|size| numbers::fits_int(vm.config.long_width, *size)) else {
        return Err(vm.type_error("buffer_size must be an integer"));
    };

    if usize::try_from(size).is_ok_and(|size| size == this.buffer_size.get()) {
        return Ok(());
    }
    if size <= 0 {
        return Err(vm.raise(ExceptionKind::ValueError, "buffer_size must be greater than zero"));
    }
    let Some(size) = i32::try_from(size).ok().and_then(|size| usize::try_from(size).ok()) else {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("buffer_size must not be greater than {}", i32::MAX)));
    };

    // C ignores the result of this flush but leaves its exception set,
    // so the next exception check raises it.
    let flushed = if this.buffer_used() != 0 { this.flush(vm) } else { Ok(()) };
    *this.buffer.borrow_mut() = Some(Vec::new());
    this.buffer_size.set(size);

    match flushed {
        Err(Failure::Raised(signal)) => Err(signal),
        Ok(()) | Err(Failure::Silent) => Ok(()),
    }
}

/// `xmlparser.__setattr__` for a deletion.
fn parser_delattr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<XmlParser>(vm, &args, TYPE_NAME, "__delattr__")?;

    Err(vm.raise(ExceptionKind::RuntimeError, "Cannot delete attribute"))
}

/// The exception a failed trampoline leaves, or the `SystemError` the
/// interpreter raises for a native function that fails without one.
fn failure_signal(vm: &Vm, failure: Failure) -> Signal {
    match failure {
        Failure::Raised(signal) => signal,
        Failure::Silent => vm.raise(ExceptionKind::SystemError, "error return without exception set"),
    }
}

/// The map for an encoding expat does not know: decodes bytes 0 to 255
/// with the named codec and "replace"; U+FFFD marks an invalid byte.
pub(super) fn unknown_encoding_map(vm: &Vm, name: &[u8]) -> PyResult<[i32; 256]> {
    let template: Vec<u8> = (0..=u8::MAX).collect();
    let mut errors = Errors::new(vm, Some(PyBytes::from("replace")));

    // These names decode directly, the rest through the codec registry.
    let units = match name {
        b"utf-8" => unicode::decode_utf8(&template, true, &mut errors)?.units,
        b"latin-1" => unicode::decode_latin1(&template),
        b"mbcs" => return Err(vm.halt_unsupported("pyexpat unknown encoding 'mbcs', the host's ANSI code page")),
        b"ascii" => unicode::decode_ascii(&template, &mut errors)?,
        _ => registry_decode(vm, name, &template)?,
    };

    if units.len() != 256 {
        return Err(vm.raise(ExceptionKind::ValueError, "multi-byte encodings are not supported"));
    }

    let mut map = [0i32; 256];
    for (entry, unit) in map.iter_mut().zip(units) {
        *entry = if unit == 0xFFFD { -1 } else { i32::from(unit) };
    }

    Ok(map)
}

/// Registry decoding of `data` with errors 'replace', which must produce
/// unicode. CPython passes a `buffer` over the bytes; a `str` reads the
/// same.
fn registry_decode(vm: &Vm, name: &[u8], data: &[u8]) -> PyResult<Vec<u16>> {
    let codec = registry::lookup(vm, name)?;
    let decoder = vm.as_tuple(&codec).and_then(|items| items.get(1).cloned());
    let Some(decoder) = decoder else {
        return Err(vm.halt_unsupported("pyexpat unknown encoding with an unknown codec"));
    };

    let result = vm.call(&decoder, CallArgs::new(vec![Value::Str(PyBytes::new(data)), Value::str("replace")]))?;
    if result.is_unknown() {
        return Err(vm.halt_unsupported("pyexpat unknown encoding whose decoder result is unknown"));
    }
    let decoded = match vm.as_tuple(&result).as_deref() {
        Some([decoded, _]) => decoded.clone(),
        _ => return Err(vm.type_error("decoder must return a tuple (object,integer)")),
    };
    if decoded.is_unknown() {
        return Err(vm.halt_unsupported("pyexpat unknown encoding whose decoder result is unknown"));
    }
    let Some(text) = vm.as_text(&decoded) else {
        return Err(vm.type_error(&format!("decoder did not return an unicode object (type={})", vm.type_name(&decoded))));
    };

    Ok(text.units().to_vec())
}

/// C `long` conversion of a handler result, through `__int__` for other types.
fn int_as_long(vm: &Vm, value: &Value) -> PyResult<i64> {
    if value.is_unknown() {
        return Err(vm.halt_unsupported("pyexpat handler returned an unknown value"));
    }

    let integral = if let Some(integral) = vm.as_integral(value) {
        integral
    } else if let Some(number) = vm.as_float(value) {
        float_integral(vm, number)?
    } else {
        let Some(method) = vm.user_override(value, "__int__")? else {
            return Err(vm.type_error("an integer is required"));
        };
        let result = vm.call0(&method)?;
        if result.is_unknown() {
            return Err(vm.halt_unsupported("pyexpat handler result with an unknown __int__"));
        }
        let Some(integral) = vm.as_integral(&result) else {
            return Err(vm.type_error("nb_int should return int object"));
        };
        integral
    };

    let number = match integral {
        Integral::Int(number) => Some(number),
        Integral::Long(number) => number.to_i64(),
    };
    match number {
        Some(number) if numbers::fits_int(vm.config.long_width, number) => Ok(number),
        _ => Err(vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long")),
    }
}

/// `float.__int__`.
fn float_integral(vm: &Vm, number: f64) -> PyResult<Integral> {
    if number.is_nan() {
        return Err(vm.raise(ExceptionKind::ValueError, "cannot convert float NaN to integer"));
    }
    if number.is_infinite() {
        return Err(vm.raise(ExceptionKind::OverflowError, "cannot convert float infinity to integer"));
    }

    // A value past `i64` is past any C `long` too.
    match number.trunc().to_i64() {
        Some(whole) => Ok(Integral::Int(whole)),
        None => Err(vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long")),
    }
}

/// Strict UTF-8 decoding into UCS-2 units.
fn decode_utf8(vm: &Vm, text: &[u8]) -> PyResult<PyText> {
    let mut errors = Errors::new(vm, None);

    Ok(PyText::new(unicode::decode_utf8(text, true, &mut errors)?.units))
}

/// The bytes `strlen` covers.
fn until_nul(text: &[u8]) -> &[u8] {
    match text.iter().position(|&byte| byte == 0) {
        Some(end) => text.get(..end).unwrap_or(text),
        None => text,
    }
}

/// `(long)` of an `XML_Size`: the target's 32-bit `long` wraps values past
/// `LONG_MAX`.
fn c_long_from_size(size: u32) -> i64 {
    i64::from(size as i32)
}
