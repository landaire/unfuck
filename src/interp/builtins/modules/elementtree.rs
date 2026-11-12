//! `_elementtree`: the `Element`, `TreeBuilder`, and `XMLParser` types
//! behind `xml.etree.cElementTree`, over the expat port. The three types
//! answer attribute lookups from method tables, so their methods are not in
//! the type dicts. The module also provides `parse`, `XML`, `XMLID`,
//! `iterparse`, an `ElementTree` subclass, and the `Comment` and `PI`
//! proxies, and re-exports helpers of the pure Python `ElementTree`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::arguments::halt_on_unknown;
use crate::interp::builtins::arguments::index_value;
use crate::interp::builtins::arguments::int_argument;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::arguments::wrapper_operand;
use crate::interp::builtins::arguments::wrapper_pair;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::descriptors::new_class_entry;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::codecs::args::optional_string;
use crate::interp::builtins::modules::codecs::args::read_buffer;
use crate::interp::builtins::modules::codecs::errors::Errors;
use crate::interp::builtins::modules::codecs::unicode;
use crate::interp::builtins::modules::expat::Attributes;
use crate::interp::builtins::modules::expat::CallbackId;
use crate::interp::builtins::modules::expat::Callbacks;
use crate::interp::builtins::modules::expat::ContentModel;
use crate::interp::builtins::modules::expat::EXPAT_VERSION_INFO;
use crate::interp::builtins::modules::expat::EntityContext;
use crate::interp::builtins::modules::expat::HandlerSlot;
use crate::interp::builtins::modules::expat::Parser;
use crate::interp::builtins::modules::expat::Status;
use crate::interp::builtins::modules::expat::error_string;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_arguments;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::pyexpat::unknown_encoding_map;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::modules::stop_iteration;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::positional;
use crate::interp::builtins::receiver;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::object::NativeBinding;
use crate::interp::object::NativeFn;
use crate::interp::ops::BinaryOp;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::SliceData;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const ELEMENT_KEY: &str = "_elementtree.Element";
const TREE_BUILDER_KEY: &str = "_elementtree.TreeBuilder";
const XML_PARSER_KEY: &str = "_elementtree.XMLParser";

/// The callback of every expat handler slot the parser fills.
const HANDLER: CallbackId = CallbackId(0);

/// Module state shared by the native functions.
#[derive(Default)]
struct Glue {
    element_path: RefCell<Option<Value>>,
    copy_element: RefCell<Option<Value>>,
    deep_copy: RefCell<Option<Value>>,
    /// `ElementTree.Comment` and `ElementTree.PI`, the tags the proxies give
    /// the elements they create.
    comment_tag: RefCell<Option<Value>>,
    pi_tag: RefCell<Option<Value>>,
    /// The module's `ElementTree` class, which `parse` instantiates.
    tree_class: RefCell<Option<Value>>,
    parse_error: RefCell<Option<ObjectRef>>,
}

/// `text` or `tail`. `joined` marks a list of pieces the `TreeBuilder`
/// collected, joined on first read.
#[derive(Clone)]
struct Content {
    value: Value,
    joined: bool,
}

impl Content {
    fn plain(value: Value) -> Self {
        Self { value, joined: false }
    }
}

/// `ElementObjectExtra`.
struct Extra {
    attrib: Value,
    children: Vec<Value>,
}

impl Extra {
    fn new() -> Self {
        Self { attrib: Value::None, children: Vec::new() }
    }
}

/// An `ElementObject`.
struct Element {
    tag: RefCell<Value>,
    text: RefCell<Content>,
    tail: RefCell<Content>,
    /// `None` until the element gets attributes or children.
    extra: RefCell<Option<Extra>>,
}

impl_native_data!(Element, "Element");

impl Element {
    /// An empty exact dict stands for no attributes.
    fn new(vm: &Vm, tag: Value, attrib: Value) -> PyResult<Self> {
        let attrib = if is_exact_dict(vm, &attrib) && dict_size(vm, &attrib)? == 0 { Value::None } else { attrib };
        let extra = if attrib.is_none() { None } else { Some(Extra { attrib, children: Vec::new() }) };

        Ok(Self { tag: RefCell::new(tag), text: RefCell::new(Content::plain(Value::None)), tail: RefCell::new(Content::plain(Value::None)), extra: RefCell::new(extra) })
    }

    fn content(&self, slot: Slot) -> &RefCell<Content> {
        match slot {
            Slot::Text => &self.text,
            Slot::Tail => &self.tail,
        }
    }

    /// Runs `body` on the extra part, created first when missing.
    fn with_extra<R>(&self, body: impl FnOnce(&mut Extra) -> R) -> R {
        let mut extra = self.extra.borrow_mut();

        body(extra.get_or_insert_with(Extra::new))
    }

    /// The child count; `None` without an extra part.
    fn extra_length(&self) -> Option<usize> {
        self.extra.borrow().as_ref().map(|extra| extra.children.len())
    }

    fn length(&self) -> usize {
        self.extra_length().unwrap_or(0)
    }

    fn children(&self) -> Vec<Value> {
        self.extra.borrow().as_ref().map(|extra| extra.children.clone()).unwrap_or_default()
    }

    /// The attrib of the extra part; `None` without one.
    fn attrib(&self) -> Option<Value> {
        self.extra.borrow().as_ref().map(|extra| extra.attrib.clone())
    }

    /// Appends a subelement.
    fn append(&self, child: Value) {
        self.with_extra(|extra| extra.children.push(child));
    }

    /// `Element.attrib` after creating the extra part: an attrib of
    /// `None` is replaced by a new dict.
    fn attrib_dict(&self, vm: &Vm) -> Value {
        self.with_extra(|extra| {
            if extra.attrib.is_none() {
                extra.attrib = Value::Object(vm.new_dict());
            }
            extra.attrib.clone()
        })
    }
}

#[derive(Clone, Copy)]
enum Slot {
    Text,
    Tail,
}

/// A failed join of a text list.
enum JoinFailure {
    /// Raised before the list went to `join`; the element still owns it.
    Raised(Signal),
    /// The `join` call failed after 2.7.12 released the element's
    /// reference to the list, which the element still points to.
    Released,
}

impl JoinFailure {
    /// A failed read whose exception is already set.
    fn into_signal(self, vm: &Vm) -> Signal {
        match self {
            Self::Raised(signal) => signal,
            Self::Released => vm.halt_unsupported("Element text or tail whose join failed: 2.7.12 has freed the list the element still holds"),
        }
    }
}

/// The `events` list of `_setevents` and the event names it reports.
struct Events {
    list: Value,
    start: Option<Value>,
    end: Option<Value>,
    start_ns: Option<Value>,
    end_ns: Option<Value>,
}

#[derive(Clone, Copy)]
enum Event {
    Start,
    End,
    StartNs,
    EndNs,
}

impl Events {
    fn new(list: Value) -> Self {
        Self { list, start: None, end: None, start_ns: None, end_ns: None }
    }

    fn action(&self, event: Event) -> Option<&Value> {
        match event {
            Event::Start => self.start.as_ref(),
            Event::End => self.end.as_ref(),
            Event::StartNs => self.start_ns.as_ref(),
            Event::EndNs => self.end_ns.as_ref(),
        }
    }
}

/// A `TreeBuilderObject`.
struct TreeBuilder {
    root: RefCell<Option<Value>>,
    /// `this`: the open element, or `None`.
    current: RefCell<Value>,
    /// `last`: the element most recently opened or closed, or `None`.
    last: RefCell<Value>,
    /// The character data since the last start or end tag.
    data: RefCell<Option<Value>>,
    /// The enclosing open elements (`stack` up to `index`).
    stack: RefCell<Vec<Value>>,
    /// `None` until `_setevents`.
    events: RefCell<Option<Events>>,
}

impl_native_data!(TreeBuilder, "TreeBuilder");

impl TreeBuilder {
    fn new() -> Self {
        Self {
            root: RefCell::new(None),
            current: RefCell::new(Value::None),
            last: RefCell::new(Value::None),
            data: RefCell::new(None),
            stack: RefCell::new(Vec::new()),
            events: RefCell::new(None),
        }
    }

    /// Stores the collected data as the text of `last` when it is the open
    /// element, else as its tail.
    fn flush_data(&self, vm: &Vm) {
        let Some(data) = self.data.borrow_mut().take() else {
            return;
        };
        let last = self.last.borrow().clone();
        // Data is collected only once an element exists.
        let Some(element) = native_data::<Element>(&last) else {
            return;
        };

        let joined = is_exact_list(vm, &data);
        let slot = if vm.is_same(&self.current.borrow(), &last) { Slot::Text } else { Slot::Tail };
        *element.content(slot).borrow_mut() = Content { value: data, joined };
    }

    fn append_event(&self, vm: &Vm, event: Event, node: Value) -> PyResult<()> {
        let pending = {
            let events = self.events.borrow();
            events.as_ref().and_then(|events| events.action(event).map(|action| (events.list.clone(), action.clone())))
        };
        let Some((list, action)) = pending else {
            return Ok(());
        };

        vm.list_append(&list, Value::tuple(vec![action, node]))
    }

    /// Whether `start-ns` events are collected.
    fn reports_start_ns(&self) -> bool {
        self.events.borrow().as_ref().is_some_and(|events| events.start_ns.is_some())
    }

    fn has_events(&self) -> bool {
        self.events.borrow().is_some()
    }

    fn handle_start(&self, vm: &Vm, tag: Value, attrib: Value) -> PyResult<Value> {
        self.flush_data(vm);

        let node = new_element(vm, Element::new(vm, tag, attrib)?)?;
        let current = self.current.borrow().clone();
        match native_data::<Element>(&current) {
            Some(parent) => parent.append(node.clone()),
            None => {
                if self.root.borrow().is_some() {
                    return Err(parse_error(vm, "multiple elements on top level"));
                }
                *self.root.borrow_mut() = Some(node.clone());
            }
        }

        self.stack.borrow_mut().push(current);
        *self.current.borrow_mut() = node.clone();
        *self.last.borrow_mut() = node.clone();
        self.append_event(vm, Event::Start, node.clone())?;

        Ok(node)
    }

    /// The first piece is kept as is; more pieces collect in a list whose
    /// joined result is the text.
    fn handle_data(&self, vm: &Vm, data: Value) -> PyResult<Value> {
        let existing = self.data.borrow_mut().take();
        let collected = match existing {
            None => {
                // Data before the first start tag is ignored.
                if self.last.borrow().is_none() {
                    return Ok(Value::None);
                }
                data
            }
            Some(existing) if is_exact_list(vm, &existing) => {
                let appended = vm.list_append(&existing, data);
                *self.data.borrow_mut() = Some(existing);
                appended?;
                return Ok(Value::None);
            }
            Some(existing) => vm.new_list(vec![existing, data]),
        };
        *self.data.borrow_mut() = Some(collected);

        Ok(Value::None)
    }

    fn handle_end(&self, vm: &Vm) -> PyResult<Value> {
        self.flush_data(vm);

        let Some(parent) = self.stack.borrow_mut().pop() else {
            return Err(vm.raise(ExceptionKind::IndexError, "pop from empty stack"));
        };
        let closed = std::mem::replace(&mut *self.current.borrow_mut(), parent);
        *self.last.borrow_mut() = closed.clone();
        self.append_event(vm, Event::End, closed.clone())?;

        Ok(closed)
    }

    fn done(&self) -> Value {
        self.root.borrow().clone().unwrap_or(Value::None)
    }
}

/// The target methods the parser looks up once.
struct TargetMethods {
    start: Option<Value>,
    data: Option<Value>,
    end: Option<Value>,
    comment: Option<Value>,
    pi: Option<Value>,
    close: Option<Value>,
}

/// An `XMLParserObject`.
struct XmlParser {
    /// Borrowed while a parse runs; a target callback that parses with the
    /// same object finds it borrowed.
    parser: RefCell<Parser>,
    target: Value,
    entity: ObjectRef,
    /// `names`: universal names by raw expat name.
    names: RefCell<HashMap<Vec<u8>, Value>>,
    methods: TargetMethods,
}

impl_native_data!(XmlParser, "XMLParser");

impl XmlParser {
    fn tree_builder(&self) -> Option<&TreeBuilder> {
        native_data::<TreeBuilder>(&self.target)
    }

    /// `uri}name` becomes `{uri}name`, decoded as other text is decoded
    /// and cached by the raw name.
    fn universal_name(&self, vm: &Vm, name: &[u8]) -> PyResult<Value> {
        let name = until_nul(name);
        if let Some(found) = self.names.borrow().get(name) {
            return Ok(found.clone());
        }

        let value = if name.contains(&b'}') {
            let mut universal = Vec::with_capacity(name.len() + 1);
            universal.push(b'{');
            universal.extend_from_slice(name);
            make_string(vm, &universal)?
        } else {
            make_string(vm, name)?
        };
        self.names.borrow_mut().insert(name.to_vec(), value.clone());

        Ok(value)
    }

    /// The attrib dict built from expat's name/value array.
    fn attributes(&self, vm: &Vm, attributes: &Attributes<'_>) -> PyResult<Value> {
        let dict = vm.new_dict();
        let mut index = 0;
        while let (Some(name), Some(value)) = (attributes.get(index), attributes.get(index + 1)) {
            let key = self.universal_name(vm, name);
            let value = make_string(vm, until_nul(value));
            // Both conversions run; the later failure is the one left set.
            let (key, value) = match (key, value) {
                (_, Err(signal)) | (Err(signal), _) => return Err(signal),
                (Ok(key), Ok(value)) => (key, value),
            };
            vm.dict_set(&dict, key, value)?;
            index += 2;
        }

        Ok(Value::Object(dict))
    }

    /// A Python exception the handlers left set wins over the expat error.
    fn parse(&self, vm: &Vm, data: &[u8], is_final: bool) -> PyResult<()> {
        let Ok(mut parser) = self.parser.try_borrow_mut() else {
            return Err(vm.halt_unsupported("XMLParser parse from a target callback of the same parser"));
        };

        let mut handlers = Handlers { vm, owner: self, error: None };
        let status = parser.parse(&mut handlers, data, is_final);
        if let Some(signal) = handlers.error {
            return Err(signal);
        }
        if status != Status::Error {
            return Ok(());
        }

        let code = parser.error_code() as i32;
        let line = parser.current_line_number();
        let column = parser.current_column_number();
        drop(parser);

        // An unknown error code prints as "(null)".
        Err(position_error(vm, error_string(code).unwrap_or("(null)"), line, column))
    }

    /// Installs both namespace declaration handlers.
    fn install_namespace_handlers(&self, vm: &Vm) -> PyResult<()> {
        let Ok(mut parser) = self.parser.try_borrow_mut() else {
            return Err(vm.halt_unsupported("XMLParser._setevents from a target callback of the same parser"));
        };
        parser.set_handler(HandlerSlot::StartNamespaceDecl, Some(HANDLER));
        parser.set_handler(HandlerSlot::EndNamespaceDecl, Some(HANDLER));

        Ok(())
    }
}

/// The expat handlers of one parse.
struct Handlers<'a> {
    vm: &'a Vm,
    owner: &'a XmlParser,
    /// The exception the latest failing handler set. Expat keeps calling
    /// the handlers and the parse raises it afterwards. A halt stops expat.
    error: Option<Signal>,
}

impl Handlers<'_> {
    fn halted(&self) -> bool {
        matches!(self.error, Some(Signal::Halt(_)))
    }

    /// Leaves `signal` set, replacing an earlier exception.
    fn fail(&mut self, parser: &mut Parser, signal: Signal) {
        if self.halted() {
            return;
        }
        if matches!(signal, Signal::Halt(_)) {
            parser.stop(false);
        }

        self.error = Some(signal);
    }

    fn check<T>(&mut self, parser: &mut Parser, result: PyResult<T>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(signal) => {
                self.fail(parser, signal);
                None
            }
        }
    }

    /// Calls a target method. After an earlier handler failed, CPython runs
    /// the method with that exception still pending, which code the method
    /// reaches can observe or clear; the interpreter does not model it.
    fn call_target(&mut self, parser: &mut Parser, method: &Value, args: Vec<Value>) {
        if self.error.is_some() {
            let halt = self.vm.halt_unsupported("_elementtree target method called while an earlier handler's exception is set");
            self.fail(parser, halt);
            return;
        }

        if let Err(signal) = self.vm.call(method, CallArgs::new(args)) {
            self.fail(parser, signal);
        }
    }

    /// The undefined entity error of the default handler.
    fn undefined_entity(&mut self, parser: &mut Parser, key: &Value) {
        // A `unicode` key gives an unpredictable name.
        let Some(name) = self.vm.as_str_bytes(key) else {
            let halt = self.vm.halt_unsupported("undefined entity with a non-ASCII name: 2.7.12 formats the unicode object as a C string");
            self.fail(parser, halt);
            return;
        };
        let shown = name.as_bytes().get(..100).unwrap_or(name.as_bytes());
        let message = format!("undefined entity &{};", String::from_utf8_lossy(shown));

        let line = parser.current_line_number();
        let column = parser.current_column_number();
        let signal = position_error(self.vm, &message, line, column);
        self.fail(parser, signal);
    }
}

impl Callbacks for Handlers<'_> {
    fn start_element(&mut self, parser: &mut Parser, _callback: CallbackId, name: &[u8], attributes: Attributes<'_>) {
        if self.halted() {
            return;
        }
        let (vm, owner) = (self.vm, self.owner);

        let Some(tag) = self.check(parser, owner.universal_name(vm, name)) else {
            return;
        };
        let attrib = if attributes.is_empty() {
            Value::None
        } else {
            let Some(attrib) = self.check(parser, owner.attributes(vm, &attributes)) else {
                return;
            };
            attrib
        };

        if let Some(builder) = owner.tree_builder() {
            let result = builder.handle_start(vm, tag, attrib);
            self.check(parser, result);
            return;
        }
        let Some(method) = &owner.methods.start else {
            return;
        };
        let attrib = if attrib.is_none() { Value::Object(vm.new_dict()) } else { attrib };
        self.call_target(parser, method, vec![tag, attrib]);
    }

    fn end_element(&mut self, parser: &mut Parser, _callback: CallbackId, name: &[u8]) {
        if self.halted() {
            return;
        }
        let (vm, owner) = (self.vm, self.owner);

        // The tree builder ignores the end tag's name.
        if let Some(builder) = owner.tree_builder() {
            let result = builder.handle_end(vm);
            self.check(parser, result);
            return;
        }
        let Some(method) = &owner.methods.end else {
            return;
        };
        let Some(tag) = self.check(parser, owner.universal_name(vm, name)) else {
            return;
        };
        self.call_target(parser, method, vec![tag]);
    }

    fn character_data(&mut self, parser: &mut Parser, _callback: CallbackId, data: &[u8]) {
        if self.halted() {
            return;
        }
        let (vm, owner) = (self.vm, self.owner);

        let Some(data) = self.check(parser, make_string(vm, data)) else {
            return;
        };
        if let Some(builder) = owner.tree_builder() {
            let result = builder.handle_data(vm, data);
            self.check(parser, result);
            return;
        }
        if let Some(method) = &owner.methods.data {
            self.call_target(parser, method, vec![data]);
        }
    }

    fn processing_instruction(&mut self, parser: &mut Parser, _callback: CallbackId, target: &[u8], data: &[u8]) {
        if self.halted() {
            return;
        }
        let (vm, owner) = (self.vm, self.owner);
        let Some(method) = &owner.methods.pi else {
            return;
        };

        let target = make_string(vm, until_nul(target));
        let data = make_string(vm, until_nul(data));
        let arguments = match (target, data) {
            (_, Err(signal)) | (Err(signal), _) => {
                self.fail(parser, signal);
                return;
            }
            (Ok(target), Ok(data)) => vec![target, data],
        };
        self.call_target(parser, method, arguments);
    }

    fn comment(&mut self, parser: &mut Parser, _callback: CallbackId, data: &[u8]) {
        if self.halted() {
            return;
        }
        let (vm, owner) = (self.vm, self.owner);
        let Some(method) = &owner.methods.comment else {
            return;
        };

        let Some(comment) = self.check(parser, make_string(vm, until_nul(data))) else {
            return;
        };
        self.call_target(parser, method, vec![comment]);
    }

    fn start_cdata_section(&mut self, _parser: &mut Parser, _callback: CallbackId) {
        // Not installed by _elementtree.
    }

    fn end_cdata_section(&mut self, _parser: &mut Parser, _callback: CallbackId) {
        // Not installed by _elementtree.
    }

    /// Entity references expat could not expand resolve through the
    /// parser's `entity` dict.
    fn default(&mut self, parser: &mut Parser, _callback: CallbackId, data: &[u8]) {
        if self.halted() {
            return;
        }
        let (vm, owner) = (self.vm, self.owner);

        if data.len() < 2 || data.first() != Some(&b'&') {
            return;
        }
        let Some(name) = data.get(1..data.len() - 1) else {
            return;
        };
        let Some(key) = self.check(parser, make_string(vm, name)) else {
            return;
        };

        let lookup = dict_lookup(vm, &Value::Object(Rc::clone(&owner.entity)), &key);
        let Some(found) = self.check(parser, lookup) else {
            return;
        };
        let Some(value) = found else {
            // The first error is reported, not the last.
            if self.error.is_none() {
                self.undefined_entity(parser, &key);
            }
            return;
        };

        if let Some(builder) = owner.tree_builder() {
            let result = builder.handle_data(vm, value);
            self.check(parser, result);
            return;
        }
        if let Some(method) = &owner.methods.data {
            self.call_target(parser, method, vec![value]);
        }
    }

    fn start_doctype_decl(&mut self, _parser: &mut Parser, _callback: CallbackId, _name: Option<&[u8]>, _system_id: Option<&[u8]>, _public_id: Option<&[u8]>, _has_internal_subset: bool) {
        // Not installed by _elementtree.
    }

    fn end_doctype_decl(&mut self, _parser: &mut Parser, _callback: CallbackId) {
        // Not installed by _elementtree.
    }

    fn entity_decl(
        &mut self,
        _parser: &mut Parser,
        _callback: CallbackId,
        _name: &[u8],
        _is_parameter_entity: bool,
        _value: Option<&[u8]>,
        _base: Option<&[u8]>,
        _system_id: Option<&[u8]>,
        _public_id: Option<&[u8]>,
        _notation_name: Option<&[u8]>,
    ) {
        // Not installed by _elementtree.
    }

    fn unparsed_entity_decl(&mut self, _parser: &mut Parser, _callback: CallbackId, _name: &[u8], _base: Option<&[u8]>, _system_id: &[u8], _public_id: Option<&[u8]>, _notation_name: &[u8]) {
        // Not installed by _elementtree.
    }

    fn notation_decl(&mut self, _parser: &mut Parser, _callback: CallbackId, _name: &[u8], _base: Option<&[u8]>, _system_id: Option<&[u8]>, _public_id: Option<&[u8]>) {
        // Not installed by _elementtree.
    }

    /// Installed by `_setevents` on a tree builder target.
    fn start_namespace_decl(&mut self, parser: &mut Parser, _callback: CallbackId, prefix: Option<&[u8]>, uri: Option<&[u8]>) {
        if self.error.is_some() {
            return;
        }
        let (vm, owner) = (self.vm, self.owner);
        let Some(builder) = owner.tree_builder() else {
            return;
        };
        if !builder.reports_start_ns() {
            return;
        }

        let Some(uri) = self.check(parser, optional_string_value(vm, uri)) else {
            return;
        };
        let Some(prefix) = self.check(parser, optional_string_value(vm, prefix)) else {
            return;
        };
        let result = builder.append_event(vm, Event::StartNs, Value::tuple(vec![prefix, uri]));
        self.check(parser, result);
    }

    fn end_namespace_decl(&mut self, parser: &mut Parser, _callback: CallbackId, _prefix: Option<&[u8]>) {
        if self.error.is_some() {
            return;
        }
        let (vm, owner) = (self.vm, self.owner);
        let Some(builder) = owner.tree_builder() else {
            return;
        };
        if !builder.has_events() {
            return;
        }

        let result = builder.append_event(vm, Event::EndNs, Value::None);
        self.check(parser, result);
    }

    fn not_standalone(&mut self, _parser: &mut Parser, _callback: CallbackId) -> bool {
        // Not installed by _elementtree, so expat never asks.
        true
    }

    fn external_entity_ref(&mut self, _parser: &mut Parser, _callback: CallbackId, _context: EntityContext<'_>, _base: Option<&[u8]>, _system_id: Option<&[u8]>, _public_id: Option<&[u8]>) -> bool {
        // Not installed by _elementtree, so expat never asks.
        true
    }

    fn skipped_entity(&mut self, _parser: &mut Parser, _callback: CallbackId, _name: &[u8], _is_parameter_entity: bool) {
        // Not installed by _elementtree.
    }

    fn unknown_encoding(&mut self, parser: &mut Parser, _callback: CallbackId, name: &[u8]) -> Option<[i32; 256]> {
        if self.halted() {
            return None;
        }

        let map = unknown_encoding_map(self.vm, until_nul(name));
        self.check(parser, map)
    }

    fn xml_decl(&mut self, _parser: &mut Parser, _callback: CallbackId, _version: Option<&[u8]>, _encoding: Option<&[u8]>, _standalone: i32) {
        // Not installed by _elementtree.
    }

    fn element_decl(&mut self, _parser: &mut Parser, _callback: CallbackId, _name: &[u8], _model: ContentModel) {
        // Not installed by _elementtree.
    }

    fn attlist_decl(&mut self, _parser: &mut Parser, _callback: CallbackId, _element_name: &[u8], _attribute_name: &[u8], _attribute_type: &[u8], _default: Option<&[u8]>, _is_required: bool) {
        // Not installed by _elementtree.
    }
}

/// Helpers of the pure Python `ElementTree` the module re-exports.
const ELEMENT_TREE_EXPORTS: [&str; 7] = ["QName", "dump", "fromstringlist", "iselement", "register_namespace", "tostring", "tostringlist"];

/// `VERSION` and `__version__` of the module.
const MODULE_VERSION: &str = "1.0.6";

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(
        vm,
        module,
        &[
            function("Element", element_factory),
            function("SubElement", sub_element),
            function("TreeBuilder", tree_builder_factory),
            function("XMLParser", xml_parser_factory),
            function("XMLTreeBuilder", xml_parser_factory),
            function("XMLID", xml_id),
            function("parse", parse_function),
        ],
    )?;
    // `fromstring` is the same object as `XML`.
    let xml = vm.new_native("XML", xml_function, NativeBinding::Function, Some(Rc::clone(module)));
    set_attribute(vm, module, "XML", xml.clone())?;
    set_attribute(vm, module, "fromstring", xml)?;

    let deep_copy = vm.getattr_str(&vm.import_module("copy")?, "deepcopy")?;
    let element_tree = import_either(vm, "xml.etree.ElementTree", "ElementTree")?;
    let element_path = import_either(vm, "xml.etree.ElementPath", "ElementPath")?;
    for name in ELEMENT_TREE_EXPORTS {
        set_attribute(vm, module, name, vm.getattr_str(&element_tree, name)?)?;
    }
    set_attribute(vm, module, "ElementPath", element_path.clone())?;
    set_attribute(vm, module, "VERSION", Value::str(MODULE_VERSION))?;
    set_attribute(vm, module, "__version__", Value::str(MODULE_VERSION))?;

    let glue = vm.native_state::<Glue>();
    *glue.element_path.borrow_mut() = Some(element_path);
    *glue.deep_copy.borrow_mut() = Some(deep_copy);
    *glue.copy_element.borrow_mut() = Some(vm.new_native_function("copyelement", copy_element_function));
    *glue.comment_tag.borrow_mut() = Some(vm.getattr_str(&element_tree, "Comment")?);
    *glue.pi_tag.borrow_mut() = Some(vm.getattr_str(&element_tree, "PI")?);

    let tree_base = vm.getattr_str(&element_tree, "ElementTree")?;
    let tree_class = new_python_class(vm, "ElementTree", tree_base, &[("parse", tree_parse)])?;
    *glue.tree_class.borrow_mut() = Some(tree_class.clone());
    set_attribute(vm, module, "ElementTree", tree_class)?;

    let object = Value::Object(Rc::clone(&vm.types().object));
    let iterparse = new_python_class(vm, "iterparse", object, &[("__init__", iterparse_init), ("__iter__", iterparse_iter), ("next", iterparse_next)])?;
    vm.setattr_str(&iterparse, "root", Value::None)?;
    set_attribute(vm, module, "iterparse", iterparse)?;

    set_attribute(vm, module, "Comment", new_proxy(vm, "CommentProxy", comment_call, comment_compare)?)?;
    let pi = new_proxy(vm, "PIProxy", pi_call, pi_compare)?;
    set_attribute(vm, module, "PI", pi.clone())?;
    set_attribute(vm, module, "ProcessingInstruction", pi)?;

    // Importing this module imports pyexpat, and fails when that fails.
    vm.import_module("pyexpat")?;

    let syntax_error = Rc::clone(vm.types().exception(ExceptionKind::SyntaxError));
    let parse_error = new_exception_class(vm, "cElementTree", "ParseError", &syntax_error)?;
    *glue.parse_error.borrow_mut() = Some(Rc::clone(&parse_error));

    set_attribute(vm, module, "ParseError", Value::Object(parse_error))
}

fn create_element_type(vm: &Vm) -> PyResult<ObjectRef> {
    const METHODS: &[MethodSpec] = &[
        method("__getattribute__", element_getattribute),
        method("__setattr__", element_setattr),
        method("__delattr__", element_delattr),
        method("__repr__", element_repr),
        method("__len__", element_len),
        method("__getitem__", element_getitem),
        method("__setitem__", element_setitem),
        method("__delitem__", element_delitem),
    ];

    new_final_type(vm, TypeSpec { name: "Element", module: "__builtin__", base: None, layout: Layout::Native, instance_dict: false, methods: METHODS })
}

/// The module never readies the `TreeBuilder` and `XMLParser` types; the
/// first attribute lookup on the type does.
fn create_tree_builder_type(vm: &Vm) -> PyResult<ObjectRef> {
    const METHODS: &[MethodSpec] = &[method("__getattribute__", tree_builder_getattribute)];

    let class = new_final_type(vm, TypeSpec { name: "TreeBuilder", module: "__builtin__", base: None, layout: Layout::Native, instance_dict: false, methods: METHODS })?;
    vm.mark_type_unready(&class);

    Ok(class)
}

fn create_xml_parser_type(vm: &Vm) -> PyResult<ObjectRef> {
    const METHODS: &[MethodSpec] = &[method("__getattribute__", xml_parser_getattribute)];

    let class = new_final_type(vm, TypeSpec { name: "XMLParser", module: "__builtin__", base: None, layout: Layout::Native, instance_dict: false, methods: METHODS })?;
    vm.mark_type_unready(&class);

    Ok(class)
}

fn glue(vm: &Vm) -> Rc<Glue> {
    vm.native_state::<Glue>()
}

/// A value the module set up at import, or `RuntimeError` when it is absent.
fn helper(vm: &Vm, cell: &RefCell<Option<Value>>, name: &str) -> PyResult<Value> {
    cell.borrow().clone().ok_or_else(|| vm.raise(ExceptionKind::RuntimeError, &format!("{name} helper not found")))
}

fn new_element(vm: &Vm, element: Element) -> PyResult<Value> {
    let class = native_type(vm, ELEMENT_KEY, create_element_type)?;

    Ok(new_native_object(vm, &class, element))
}

fn new_tree_builder(vm: &Vm) -> PyResult<Value> {
    let class = native_type(vm, TREE_BUILDER_KEY, create_tree_builder_type)?;

    Ok(new_native_object(vm, &class, TreeBuilder::new()))
}

/// Raises `ParseError` with `message`.
fn parse_error(vm: &Vm, message: &str) -> Signal {
    match parse_error_class(vm) {
        Ok(class) => vm.raise_string(&class, Value::str(message)),
        Err(signal) => signal,
    }
}

fn parse_error_class(vm: &Vm) -> PyResult<ObjectRef> {
    glue(vm).parse_error.borrow().clone().ok_or_else(|| vm.halt_unsupported("cElementTree.ParseError before _elementtree finished initializing"))
}

/// A `ParseError` whose `position` is `(line, column)`.
fn position_error(vm: &Vm, message: &str, line: u32, column: u32) -> Signal {
    // Line and column print as signed 32-bit values.
    let line = i64::from(line as i32);
    let column = i64::from(column as i32);
    let text = format!("{message}: line {line}, column {column}");

    let class = match parse_error_class(vm) {
        Ok(class) => class,
        Err(signal) => return signal,
    };
    let error = match vm.call(&Value::Object(class), CallArgs::new(vec![Value::str(&text)])) {
        Ok(error) => error,
        Err(signal) => return signal,
    };
    if let Err(signal) = vm.setattr_str(&error, "position", Value::tuple(vec![Value::Int(line), Value::Int(column)])) {
        return signal;
    }

    Signal::Raise(error)
}

/// ASCII stays `str`; anything else decodes as UTF-8.
fn make_string(vm: &Vm, bytes: &[u8]) -> PyResult<Value> {
    if bytes.is_ascii() {
        return Ok(Value::Str(PyBytes::new(bytes)));
    }

    let mut errors = Errors::new(vm, None);
    Ok(Value::Unicode(PyText::new(unicode::decode_utf8(bytes, true, &mut errors)?.units)))
}

/// Optional text as a string, or `""` when absent.
fn optional_string_value(vm: &Vm, text: Option<&[u8]>) -> PyResult<Value> {
    match text {
        Some(text) => make_string(vm, until_nul(text)),
        None => Ok(Value::str("")),
    }
}

/// The bytes `strlen` covers.
fn until_nul(text: &[u8]) -> &[u8] {
    match text.iter().position(|&byte| byte == 0) {
        Some(end) => text.get(..end).unwrap_or(text),
        None => text,
    }
}

fn is_exact_dict(vm: &Vm, value: &Value) -> bool {
    value.as_object().is_some_and(|object| Rc::ptr_eq(&object.class(), &vm.types().dict))
}

fn is_exact_list(vm: &Vm, value: &Value) -> bool {
    value.as_object().is_some_and(|object| Rc::ptr_eq(&object.class(), &vm.types().list))
}

/// The dict object of a dict or dict subclass.
fn dict_object(value: &Value) -> Option<&ObjectRef> {
    value.as_object().filter(|object| object.as_dict().is_some())
}

fn dict_size(vm: &Vm, value: &Value) -> PyResult<usize> {
    match dict_object(value) {
        Some(dict) => vm.dict_len(dict),
        None => Ok(0),
    }
}

/// The SystemError CPython raises for a non-dict where a dict is
/// required; `line` is the source line its message names.
fn bad_dict_call(vm: &Vm, line: u32) -> Signal {
    vm.raise(ExceptionKind::SystemError, &format!("..\\Objects\\dictobject.c:{line}: bad argument to internal function"))
}

/// The dict an operation requires; a non-dict raises SystemError.
fn require_dict<'a>(vm: &Vm, value: &'a Value, line: u32) -> PyResult<&'a ObjectRef> {
    halt_on_unknown(value, "Element attrib")?;

    dict_object(value).ok_or_else(|| bad_dict_call(vm, line))
}

/// `None` for a missing key, a non-dict, or a failed lookup, whose
/// exception is discarded.
fn dict_lookup(vm: &Vm, dict: &Value, key: &Value) -> PyResult<Option<Value>> {
    halt_on_unknown(dict, "Element attrib")?;
    let Some(dict) = dict_object(dict) else {
        return Ok(None);
    };

    match vm.dict_get(dict, key) {
        Ok(found) => Ok(found),
        Err(Signal::Raise(_)) => Ok(None),
        Err(halt) => Err(halt),
    }
}

/// The conversion error of an `O!` argument: the expected type, then `None` or the
/// type of the value given.
fn wrong_argument(vm: &Vm, function: &str, position: usize, expected: &str, value: &Value) -> Signal {
    let shown = if value.is_none() { "None".to_owned() } else { vm.type_name(value) };

    vm.type_error(&format!("{function}() argument {position} must be {expected}, not {shown}"))
}

/// The `O!` check against the `Element` type.
fn require_element<'a>(vm: &Vm, function: &str, position: usize, value: &'a Value) -> PyResult<&'a Element> {
    halt_on_unknown(value, "Element argument")?;

    native_data::<Element>(value).ok_or_else(|| wrong_argument(vm, function, position, "Element", value))
}

/// The `O!` check against the `dict` type.
fn check_dict_argument(vm: &Vm, function: &str, position: usize, value: &Value) -> PyResult<()> {
    halt_on_unknown(value, "dict argument")?;
    if dict_object(value).is_none() {
        return Err(wrong_argument(vm, function, position, "dict", value));
    }

    Ok(())
}

/// Splits counted arguments into `R` required and up to `O` optional ones.
fn split_arguments<const R: usize, const O: usize>(vm: &Vm, values: Vec<Value>) -> PyResult<([Value; R], [Option<Value>; O])> {
    let mut values = values.into_iter();
    let required: Vec<Value> = values.by_ref().take(R).collect();
    let Ok(required) = <[Value; R]>::try_from(required) else {
        return Err(vm.raise(ExceptionKind::SystemError, "argument count mismatch"));
    };
    let optional = std::array::from_fn(|_| values.next());

    Ok((required, optional))
}

/// The positional arguments after the receiver of a method, with the
/// argument count errors of a native method.
fn method_args<const R: usize, const O: usize>(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<([Value; R], [Option<Value>; O])> {
    split_arguments(vm, method_arguments(vm, args, name, R, R + O)?)
}

/// The positional arguments of a function taking keywords, whose keyword
/// arguments are left for the function.
fn function_args<const R: usize, const O: usize>(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<([Value; R], [Option<Value>; O])> {
    split_arguments(vm, positional(vm, CallArgs::new(args.positional.clone()), name, R, R + O)?)
}

/// `attrib` copied and updated with the keyword arguments; `None` when
/// neither is given.
fn merged_attributes(vm: &Vm, attrib: Option<&Value>, args: &CallArgs) -> PyResult<Value> {
    if attrib.is_none() && !args.has_keywords() {
        return Ok(Value::None);
    }

    let merged = match attrib.and_then(dict_object) {
        Some(dict) => vm.dict_copy(dict)?,
        None => vm.new_dict(),
    };
    if args.has_keywords() {
        let keywords = keyword_dict(vm, args)?;
        vm.dict_merge(&merged, &Value::Object(keywords), true)?;
    }

    Ok(Value::Object(merged))
}

/// The keyword dict of a call that accepts keywords.
fn keyword_dict(vm: &Vm, args: &CallArgs) -> PyResult<ObjectRef> {
    if let Some(dict) = &args.keyword_dict {
        return Ok(Rc::clone(dict));
    }

    let dict = vm.new_dict();
    for (name, value) in &args.keywords {
        vm.dict_set(&dict, Value::Str(name.clone()), value.clone())?;
    }

    Ok(dict)
}

/// `Element(tag, attrib={}, **extra)`.
fn element_factory(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let ([tag], [attrib]) = function_args::<1, 1>(vm, &args, "Element")?;
    if let Some(attrib) = &attrib {
        check_dict_argument(vm, "Element", 2, attrib)?;
    }

    let attrib = merged_attributes(vm, attrib.as_ref(), &args)?;

    new_element(vm, Element::new(vm, tag, attrib)?)
}

/// `SubElement(parent, tag, attrib={}, **extra)`.
fn sub_element(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let ([parent, tag], [attrib]) = function_args::<2, 1>(vm, &args, "SubElement")?;
    let parent = require_element(vm, "SubElement", 1, &parent)?;
    if let Some(attrib) = &attrib {
        check_dict_argument(vm, "SubElement", 3, attrib)?;
    }

    let attrib = merged_attributes(vm, attrib.as_ref(), &args)?;
    let element = new_element(vm, Element::new(vm, tag, attrib)?)?;
    parent.append(element.clone());

    Ok(element)
}

/// `TreeBuilder()`.
fn tree_builder_factory(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    positional(vm, args, "TreeBuilder", 0, 0)?;

    new_tree_builder(vm)
}

/// `XMLParser(target=None, encoding=None)`: the target's methods are looked
/// up once, and lookup failures are cleared.
fn xml_parser_factory(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let mut encoding = None;
    let slots = parse_with(vm, args, "XMLParser", &["target", "encoding"], 0, |vm, index, value| {
        if index == 1 {
            halt_on_unknown(&value, "XMLParser encoding")?;
            encoding = optional_string(vm, "XMLParser", 2, Some(&value))?;
        }
        Ok(value)
    })?;

    let mut parser = Parser::new(encoding.as_ref().map(PyBytes::as_bytes), Some(b'}'));
    let target = match slots.into_iter().next().flatten() {
        Some(target) => target,
        None => new_tree_builder(vm)?,
    };

    // The target's `xml` method is looked up but never called.
    target_method(vm, &target, "xml")?;
    let methods = TargetMethods {
        start: target_method(vm, &target, "start")?,
        data: target_method(vm, &target, "data")?,
        end: target_method(vm, &target, "end")?,
        comment: target_method(vm, &target, "comment")?,
        pi: target_method(vm, &target, "pi")?,
        close: target_method(vm, &target, "close")?,
    };

    parser.set_handler(HandlerSlot::StartElement, Some(HANDLER));
    parser.set_handler(HandlerSlot::EndElement, Some(HANDLER));
    parser.set_default_handler_expand(Some(HANDLER));
    parser.set_handler(HandlerSlot::CharacterData, Some(HANDLER));
    if methods.comment.is_some() {
        parser.set_handler(HandlerSlot::Comment, Some(HANDLER));
    }
    if methods.pi.is_some() {
        parser.set_handler(HandlerSlot::ProcessingInstruction, Some(HANDLER));
    }
    parser.set_handler(HandlerSlot::UnknownEncoding, Some(HANDLER));

    let class = native_type(vm, XML_PARSER_KEY, create_xml_parser_type)?;
    let parser = XmlParser { parser: RefCell::new(parser), target, entity: vm.new_dict(), names: RefCell::new(HashMap::new()), methods };

    Ok(new_native_object(vm, &class, parser))
}

/// The attribute `name` of the target, or `None` when the lookup fails.
fn target_method(vm: &Vm, target: &Value, name: &str) -> PyResult<Option<Value>> {
    match vm.getattr_str(target, name) {
        Ok(method) => Ok(Some(method)),
        Err(Signal::Raise(_)) => Ok(None),
        Err(halt) => Err(halt),
    }
}

/// The Element methods found by attribute lookup.
const ELEMENT_METHODS: [(&str, NativeFn); 21] = [
    ("clear", element_clear),
    ("get", element_get),
    ("set", element_set),
    ("find", element_find),
    ("findtext", element_findtext),
    ("findall", element_findall),
    ("append", element_append),
    ("extend", element_extend),
    ("insert", element_insert),
    ("remove", element_remove),
    ("iter", element_iter),
    ("itertext", element_itertext),
    ("iterfind", element_iterfind),
    ("getiterator", element_iter),
    ("getchildren", element_getchildren),
    ("items", element_items),
    ("keys", element_keys),
    ("makeelement", element_makeelement),
    ("__copy__", element_copy),
    ("__deepcopy__", element_deepcopy),
    ("__reduce__", element_reduce),
];

const TREE_BUILDER_METHODS: [(&str, NativeFn); 5] = [
    ("data", tree_builder_data),
    ("start", tree_builder_start),
    ("end", tree_builder_end),
    ("xml", tree_builder_xml),
    ("close", tree_builder_close),
];

const XML_PARSER_METHODS: [(&str, NativeFn); 4] = [
    ("feed", xml_parser_feed),
    ("close", xml_parser_close),
    ("_parse", xml_parser_parse),
    ("_setevents", xml_parser_setevents),
];

/// The sorted method names for `__methods__`, or the method bound to
/// `receiver`.
fn find_method(vm: &Vm, receiver: &Value, name: &[u8], methods: &[(&'static str, NativeFn)]) -> Option<Value> {
    if name == b"__methods__" {
        let mut names: Vec<&str> = methods.iter().map(|(method_name, _)| *method_name).collect();
        names.sort_unstable();
        return Some(vm.new_list(names.into_iter().map(Value::str).collect()));
    }

    let (method_name, function) = methods.iter().find(|(method_name, _)| method_name.as_bytes() == name)?;
    let owner = receiver.as_object().map(|object| object.class());

    Some(vm.new_bound_native(method_name, *function, receiver.clone(), owner))
}

/// An AttributeError whose value is the name.
fn attribute_error(vm: &Vm, name: &[u8]) -> Signal {
    let class = Rc::clone(vm.types().exception(ExceptionKind::AttributeError));

    vm.raise_string(&class, Value::Str(PyBytes::new(name)))
}

/// An attribute name as bytes.
fn attribute_name(vm: &Vm, name: &Value) -> PyResult<Vec<u8>> {
    let Some(name) = vm.as_str_bytes(name) else {
        return Err(vm.type_error(&format!("attribute name must be string, not '{}'", vm.type_name(name))));
    };

    Ok(until_nul(name.as_bytes()).to_vec())
}

/// The receiver and attribute name of a `__getattribute__` or
/// `__delattr__` call.
fn hook_target(vm: &Vm, args: CallArgs, method: &str) -> PyResult<(Value, Vec<u8>)> {
    let (target, rest) = receiver(vm, args, method)?;
    let name = wrapper_operand(vm, rest)?;

    Ok((target, attribute_name(vm, &name)?))
}

/// The receiver, attribute name, and value of a `__setattr__` call.
fn setattr_target(vm: &Vm, args: CallArgs) -> PyResult<(Value, Vec<u8>, Value)> {
    let (target, rest) = receiver(vm, args, "__setattr__")?;
    let (name, value) = wrapper_pair(vm, rest)?;

    Ok((target, attribute_name(vm, &name)?, value))
}

fn element_of<'a>(vm: &Vm, value: &'a Value, method: &str) -> PyResult<&'a Element> {
    native_data::<Element>(value).ok_or_else(|| vm.type_error(&format!("descriptor '{method}' requires a 'Element' object but received a '{}'", vm.type_name(value))))
}

fn element_getattribute(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, name) = hook_target(vm, args, "__getattribute__")?;
    let element = element_of(vm, &target, "__getattribute__")?;

    match name.as_slice() {
        b"tag" => return Ok(element.tag.borrow().clone()),
        // A failed join cannot be reproduced faithfully.
        b"text" => return read_content(vm, element, Slot::Text).map_err(|_| vm.halt_unsupported("Element.text whose join failed: 2.7.12 dereferences NULL")),
        _ => {}
    }

    if let Some(method) = find_method(vm, &target, &name, &ELEMENT_METHODS) {
        return Ok(method);
    }

    match name.as_slice() {
        b"tail" => read_content(vm, element, Slot::Tail).map_err(|failure| failure.into_signal(vm)),
        b"attrib" => Ok(element.attrib_dict(vm)),
        _ => Err(attribute_error(vm, &name)),
    }
}

/// Attribute assignment.
fn element_setattr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, name, value) = setattr_target(vm, args)?;
    let element = element_of(vm, &target, "__setattr__")?;

    match name.as_slice() {
        b"tag" => *element.tag.borrow_mut() = value,
        b"text" => *element.text.borrow_mut() = Content::plain(value),
        b"tail" => *element.tail.borrow_mut() = Content::plain(value),
        b"attrib" => element.with_extra(|extra| extra.attrib = value),
        _ => return Err(attribute_error(vm, &name)),
    }

    Ok(Value::None)
}

/// Attribute deletion.
fn element_delattr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _name) = hook_target(vm, args, "__delattr__")?;
    element_of(vm, &target, "__delattr__")?;

    Err(vm.raise(ExceptionKind::AttributeError, "can't delete element attributes"))
}

/// `Element.text` and `Element.tail`: a joined list is replaced by
/// its join on first read.
fn read_content(vm: &Vm, element: &Element, slot: Slot) -> Result<Value, JoinFailure> {
    let content = element.content(slot).borrow().clone();
    if !content.joined || !is_exact_list(vm, &content.value) {
        return Ok(content.value);
    }
    let Some(items) = vm.as_list(&content.value) else {
        return Ok(content.value);
    };

    let joined = list_join(vm, &content.value, &items)?;
    *element.content(slot).borrow_mut() = Content::plain(joined.clone());

    Ok(joined)
}

/// Joins the pieces by an empty slice of the first.
fn list_join(vm: &Vm, list: &Value, items: &[Value]) -> Result<Value, JoinFailure> {
    let first = match items {
        [] => return Ok(Value::str("")),
        [only] => return Ok(only.clone()),
        [first, ..] => first,
    };

    let joiner = vm.get_slice(first, &Value::Int(0), &Value::Int(0)).map_err(JoinFailure::Raised)?;
    let join = vm.getattr_str(&joiner, "join").map_err(JoinFailure::Raised)?;
    match vm.call1(&join, list.clone()) {
        Ok(joined) => Ok(joined),
        Err(Signal::Raise(_)) => Err(JoinFailure::Released),
        Err(halt) => Err(JoinFailure::Raised(halt)),
    }
}

fn element_clear(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let element = this::<Element>(vm, &args, "Element", "clear")?;
    method_args::<0, 0>(vm, &args, "clear")?;

    let removed = element.extra.borrow_mut().take();
    *element.text.borrow_mut() = Content::plain(Value::None);
    *element.tail.borrow_mut() = Content::plain(Value::None);
    drop(removed);

    Ok(Value::None)
}

fn element_get(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let element = this::<Element>(vm, &args, "Element", "get")?;
    let ([key], [default]) = method_args::<1, 1>(vm, &args, "get")?;
    let default = default.unwrap_or(Value::None);

    let Some(attrib) = element.attrib().filter(|attrib| !attrib.is_none()) else {
        return Ok(default);
    };

    Ok(dict_lookup(vm, &attrib, &key)?.unwrap_or(default))
}

fn element_set(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let element = this::<Element>(vm, &args, "Element", "set")?;
    let ([key, value], []) = method_args::<2, 0>(vm, &args, "set")?;

    let attrib = element.attrib_dict(vm);
    let dict = require_dict(vm, &attrib, 833)?;
    vm.dict_set(dict, key, value)?;

    Ok(Value::None)
}

/// Whether a tag outside `{...}` has a path character, or is
/// not a string at all.
fn is_path(vm: &Vm, tag: &Value) -> PyResult<bool> {
    fn scan(units: impl Iterator<Item = u16>) -> bool {
        let mut checking = true;
        for unit in units {
            match unit {
                0x7B => checking = false,
                0x7D => checking = true,
                0x2F | 0x2A | 0x5B | 0x40 | 0x2E if checking => return true,
                _ => {}
            }
        }
        false
    }

    halt_on_unknown(tag, "Element path")?;
    if let Some(text) = vm.as_text(tag) {
        return Ok(scan(text.units().iter().copied()));
    }
    if let Some(bytes) = vm.as_str_bytes(tag) {
        return Ok(scan(bytes.as_bytes().iter().map(|&byte| u16::from(byte))));
    }

    Ok(true)
}

/// Calls the `ElementPath` function `name`.
fn element_path(vm: &Vm, name: &str, arguments: Vec<Value>) -> PyResult<Value> {
    let Some(module) = glue(vm).element_path.borrow().clone() else {
        return Err(vm.raise(ExceptionKind::SystemError, "null argument to internal routine"));
    };

    vm.call_method(&module, name, arguments)
}

/// Three-way comparison, as `cmp` performs.
fn compare(vm: &Vm, left: &Value, right: &Value) -> PyResult<i64> {
    let result = vm.three_way_compare(left, right)?;
    halt_on_unknown(&result, "Element tag comparison")?;
    let Value::Int(order) = result else {
        return Err(vm.halt_unsupported("cmp() result that is not an int"));
    };

    Ok(order)
}

/// The child at `index`, read afresh after each comparison that may run
/// Python code; `None` past the end.
fn live_child(vm: &Vm, element: &Element, index: usize) -> PyResult<Option<Value>> {
    let extra = element.extra.borrow();
    let Some(extra) = extra.as_ref() else {
        return Err(vm.halt_unsupported("Element search after Python code cleared the element: C dereferences NULL"));
    };

    Ok(extra.children.get(index).cloned())
}

/// The next child after `index` that is an `Element` whose tag compares
/// equal to `tag`, with its position.
fn next_match(vm: &Vm, element: &Element, tag: &Value, mut index: usize) -> PyResult<Option<(usize, Value)>> {
    while let Some(child) = live_child(vm, element, index)? {
        if let Some(candidate) = native_data::<Element>(&child) {
            let candidate_tag = candidate.tag.borrow().clone();
            if compare(vm, &candidate_tag, tag)? == 0 {
                return Ok(Some((index, child)));
            }
        }
        index += 1;
    }

    Ok(None)
}

fn element_find(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let element = this::<Element>(vm, &args, "Element", "find")?;
    let ([tag], [namespaces]) = method_args::<1, 1>(vm, &args, "find")?;
    let namespaces = namespaces.unwrap_or(Value::None);

    if is_path(vm, &tag)? || !namespaces.is_none() {
        return element_path(vm, "find", vec![receiver_of(&args), tag, namespaces]);
    }
    if element.extra_length().is_none() {
        return Ok(Value::None);
    }

    Ok(next_match(vm, element, &tag, 0)?.map_or(Value::None, |(_, child)| child))
}

fn element_findtext(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let element = this::<Element>(vm, &args, "Element", "findtext")?;
    let ([tag], [default, namespaces]) = method_args::<1, 2>(vm, &args, "findtext")?;
    let default = default.unwrap_or(Value::None);
    let namespaces = namespaces.unwrap_or(Value::None);

    if is_path(vm, &tag)? || !namespaces.is_none() {
        return element_path(vm, "findtext", vec![receiver_of(&args), tag, default, namespaces]);
    }
    if element.extra_length().is_none() {
        return Ok(default);
    }

    let Some((_, child)) = next_match(vm, element, &tag, 0)? else {
        return Ok(default);
    };
    let Some(child) = native_data::<Element>(&child) else {
        return Ok(default);
    };
    let text = read_content(vm, child, Slot::Text).map_err(|failure| failure.into_signal(vm))?;

    Ok(if text.is_none() { Value::str("") } else { text })
}

fn element_findall(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let element = this::<Element>(vm, &args, "Element", "findall")?;
    let ([tag], [namespaces]) = method_args::<1, 1>(vm, &args, "findall")?;
    let namespaces = namespaces.unwrap_or(Value::None);

    if is_path(vm, &tag)? || !namespaces.is_none() {
        return element_path(vm, "findall", vec![receiver_of(&args), tag, namespaces]);
    }

    let mut found = Vec::new();
    if element.extra_length().is_some() {
        let mut index = 0;
        while let Some((position, child)) = next_match(vm, element, &tag, index)? {
            found.push(child);
            index = position + 1;
        }
    }

    Ok(vm.new_list(found))
}

fn element_iterfind(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<Element>(vm, &args, "Element", "iterfind")?;
    let ([tag], [namespaces]) = method_args::<1, 1>(vm, &args, "iterfind")?;

    element_path(vm, "iterfind", vec![receiver_of(&args), tag, namespaces.unwrap_or(Value::None)])
}

/// The receiver of a method call, which `this` already checked.
fn receiver_of(args: &CallArgs) -> Value {
    args.positional.first().cloned().unwrap_or(Value::None)
}

fn element_append(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let element = this::<Element>(vm, &args, "Element", "append")?;
    let ([child], []) = method_args::<1, 0>(vm, &args, "append")?;
    require_element(vm, "append", 1, &child)?;

    element.append(child);

    Ok(Value::None)
}

fn element_extend(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let element = this::<Element>(vm, &args, "Element", "extend")?;
    let ([sequence], []) = method_args::<1, 0>(vm, &args, "extend")?;

    for child in sequence_items(vm, &sequence)? {
        element.append(child);
    }

    Ok(Value::None)
}

/// The items of a sequence; a non-sequence raises this module's
/// `TypeError`.
fn sequence_items(vm: &Vm, value: &Value) -> PyResult<Vec<Value>> {
    halt_on_unknown(value, "Element children sequence")?;
    if is_exact_list(vm, value) || Rc::ptr_eq(&vm.type_of(value), &vm.types().tuple) {
        if let Some(items) = vm.as_list(value) {
            return Ok(items);
        }
        if let Some(items) = vm.as_tuple(value) {
            return Ok(items.to_vec());
        }
    }

    let collected: PyResult<Vec<Value>> = (|| {
        let iterator = vm.iter(value)?;
        let mut items = Vec::new();
        while let Some(item) = vm.next(&iterator)? {
            items.push(item);
        }
        Ok(items)
    })();
    match collected {
        Ok(items) => Ok(items),
        Err(Signal::Raise(_)) => Err(vm.type_error(&format!("expected sequence, not \"{}\"", vm.type_name(value)))),
        Err(halt) => Err(halt),
    }
}

fn element_insert(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let element = this::<Element>(vm, &args, "Element", "insert")?;
    let ([index, child], []) = method_args::<2, 0>(vm, &args, "insert")?;
    let index = int_argument(vm, &index)?;
    require_element(vm, "insert", 2, &child)?;

    element.with_extra(|extra| {
        let length = extra.children.len() as i64;
        let index = if index < 0 { index + length } else { index };
        let position = index.clamp(0, length) as usize;
        extra.children.insert(position, child);
    });

    Ok(Value::None)
}

fn element_remove(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let element = this::<Element>(vm, &args, "Element", "remove")?;
    let ([child], []) = method_args::<1, 0>(vm, &args, "remove")?;
    require_element(vm, "remove", 1, &child)?;
    let not_found = || vm.raise(ExceptionKind::ValueError, "list.remove(x): x not in list");

    if element.extra_length().is_none() {
        return Err(not_found());
    }

    let mut index = 0;
    loop {
        let Some(current) = live_child(vm, element, index)? else {
            return Err(not_found());
        };
        if vm.is_same(&current, &child) || compare(vm, &current, &child)? == 0 {
            break;
        }
        index += 1;
    }

    let removed = {
        let mut extra = element.extra.borrow_mut();
        let Some(extra) = extra.as_mut() else {
            return Err(vm.halt_unsupported("Element.remove after Python code cleared the element: C dereferences NULL"));
        };
        if index >= extra.children.len() {
            return Err(not_found());
        }
        extra.children.remove(index)
    };
    drop(removed);

    Ok(Value::None)
}

/// `iter` and `getiterator`, both parsed as `iter`.
fn element_iter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<Element>(vm, &args, "Element", "iter")?;
    let ([], [tag]) = method_args::<0, 1>(vm, &args, "iter")?;

    new_walk(vm, receiver_of(&args), WalkKind::Elements, tag)
}

fn element_itertext(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<Element>(vm, &args, "Element", "itertext")?;
    method_args::<0, 0>(vm, &args, "itertext")?;

    new_walk(vm, receiver_of(&args), WalkKind::Text, None)
}

fn element_getchildren(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let element = this::<Element>(vm, &args, "Element", "getchildren")?;
    method_args::<0, 0>(vm, &args, "getchildren")?;

    Ok(vm.new_list(element.children()))
}

fn element_items(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let element = this::<Element>(vm, &args, "Element", "items")?;
    method_args::<0, 0>(vm, &args, "items")?;

    let Some(attrib) = element.attrib().filter(|attrib| !attrib.is_none()) else {
        return Ok(vm.new_list(Vec::new()));
    };
    let dict = require_dict(vm, &attrib, 1734)?;
    let items = vm.dict_items(dict)?.into_iter().map(|(key, value)| Value::tuple(vec![key, value])).collect();

    Ok(vm.new_list(items))
}

fn element_keys(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let element = this::<Element>(vm, &args, "Element", "keys")?;
    method_args::<0, 0>(vm, &args, "keys")?;

    let Some(attrib) = element.attrib().filter(|attrib| !attrib.is_none()) else {
        return Ok(vm.new_list(Vec::new()));
    };
    let dict = require_dict(vm, &attrib, 1714)?;

    Ok(vm.new_list(vm.dict_keys(dict)?))
}

fn element_makeelement(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<Element>(vm, &args, "Element", "makeelement")?;
    let ([tag, attrib], []) = method_args::<2, 0>(vm, &args, "makeelement")?;

    let attrib = vm.dict_copy(require_dict(vm, &attrib, 1688)?)?;

    new_element(vm, Element::new(vm, tag, Value::Object(attrib))?)
}

/// A new element sharing the tag, attrib, text, tail, and children.
fn copy_element(vm: &Vm, element: &Element) -> PyResult<Value> {
    let tag = element.tag.borrow().clone();
    // `None` for an element without attributes.
    let attrib = element.attrib().unwrap_or(Value::None);

    let copy = Element::new(vm, tag, attrib)?;
    *copy.text.borrow_mut() = element.text.borrow().clone();
    *copy.tail.borrow_mut() = element.tail.borrow().clone();
    if let Some(children) = element.extra.borrow().as_ref().map(|extra| extra.children.clone()) {
        copy.with_extra(|extra| extra.children = children);
    }

    new_element(vm, copy)
}

fn element_copy(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let element = this::<Element>(vm, &args, "Element", "__copy__")?;
    method_args::<0, 0>(vm, &args, "__copy__")?;

    copy_element(vm, element)
}

fn element_deepcopy(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let element = this::<Element>(vm, &args, "Element", "__deepcopy__")?;
    let ([memo], []) = method_args::<1, 0>(vm, &args, "__deepcopy__")?;
    let deep_copy = helper(vm, &glue(vm).deep_copy, "deepcopy")?;
    let copy_of = |value: Value| vm.call(&deep_copy, CallArgs::new(vec![value, memo.clone()]));

    let tag = element.tag.borrow().clone();
    let tag = copy_of(tag)?;
    let attrib = match element.attrib() {
        Some(attrib) => copy_of(attrib)?,
        None => Value::None,
    };
    let copy = Element::new(vm, tag, attrib)?;

    let text = element.text.borrow().clone();
    *copy.text.borrow_mut() = Content { value: copy_of(text.value)?, joined: text.joined };
    let tail = element.tail.borrow().clone();
    *copy.tail.borrow_mut() = Content { value: copy_of(tail.value)?, joined: tail.joined };

    if let Some(length) = element.extra_length() {
        let mut children = Vec::with_capacity(length);
        for index in 0..length {
            // The copy's size is fixed before the children are copied.
            if element.extra_length() != Some(length) {
                return Err(vm.halt_unsupported("Element.__deepcopy__ while Python code changes the element's children"));
            }
            let Some(child) = live_child(vm, element, index)? else {
                break;
            };
            children.push(copy_of(child)?);
        }
        copy.with_extra(|extra| extra.children = children);
    }

    let copy = new_element(vm, copy)?;

    // The address truncated to a signed 32-bit integer.
    let address = vm.value_address(&receiver_of(&args));
    let key = Value::Int(i64::from(address as u32 as i32));
    halt_on_unknown(&memo, "__deepcopy__ memo")?;
    let memo = dict_object(&memo).ok_or_else(|| bad_dict_call(vm, 833))?;
    vm.dict_set(memo, key, copy.clone())?;

    Ok(copy)
}

/// `__reduce__`: the copy, rebuilt by `copyelement`, which returns its
/// argument.
fn element_reduce(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let element = this::<Element>(vm, &args, "Element", "__reduce__")?;
    method_args::<0, 0>(vm, &args, "__reduce__")?;
    let copy_helper = helper(vm, &glue(vm).copy_element, "copyelement")?;

    let copy = copy_element(vm, element)?;

    Ok(Value::tuple(vec![copy_helper, Value::tuple(vec![copy])]))
}

fn element_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = receiver(vm, args, "__repr__")?;
    let element = element_of(vm, &target, "__repr__")?;
    wrapper_arguments(vm, rest, 0)?;

    let tag = element.tag.borrow().clone();
    let tag_repr = vm.repr(&tag)?;
    if tag_repr.is_unknown() {
        return Ok(tag_repr);
    }
    let Some(tag_repr) = vm.as_str_bytes(&tag_repr) else {
        return Err(vm.halt_unsupported("Element repr whose tag repr is not a str"));
    };

    let mut text = b"<Element ".to_vec();
    text.extend_from_slice(until_nul(tag_repr.as_bytes()));
    text.extend_from_slice(format!(" at {:#x}>", vm.value_address(&target)).as_bytes());

    Ok(Value::Str(PyBytes::new(text)))
}

fn element_len(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = receiver(vm, args, "__len__")?;
    let element = element_of(vm, &target, "__len__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(Value::Int(element.length() as i64))
}

/// The integer value of `index`, or `None` when it is not an integer.
fn index_operand(vm: &Vm, index: &Value) -> PyResult<Option<i64>> {
    halt_on_unknown(index, "Element index")?;
    if vm.as_integral(index).is_none() && vm.user_override(index, "__index__")?.is_none() {
        return Ok(None);
    }

    match index_value(vm, index) {
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::OverflowError) => Err(vm.raise(ExceptionKind::IndexError, &format!("cannot fit '{}' into an index-sized integer", vm.type_name(index)))),
        result => result.map(Some),
    }
}

fn element_getitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = receiver(vm, args, "__getitem__")?;
    let element = element_of(vm, &target, "__getitem__")?;
    let index = wrapper_operand(vm, rest)?;

    if let Some(position) = index_operand(vm, &index)? {
        let length = element.extra_length();
        let position = match length {
            Some(length) if position < 0 => position + length as i64,
            _ => position,
        };
        let child = usize::try_from(position).ok().and_then(|position| element.extra.borrow().as_ref().and_then(|extra| extra.children.get(position).cloned()));
        return child.ok_or_else(|| vm.raise(ExceptionKind::IndexError, "child index out of range"));
    }

    let Some(slice) = vm.slice_of(&index) else {
        return Err(vm.type_error("element indices must be integers"));
    };
    let Some(length) = element.extra_length() else {
        return Ok(vm.new_list(Vec::new()));
    };
    let indices = vm.slice_indices(&slice, length)?;

    // The bounds are computed before `__index__` ran.
    let items = {
        let extra = element.extra.borrow();
        extra.as_ref().and_then(|extra| indices.positions().map(|position| extra.children.get(position).cloned()).collect::<Option<Vec<Value>>>())
    };
    let Some(items) = items else {
        return Err(vm.halt_unsupported("Element slice after __index__ removed children"));
    };

    Ok(vm.new_list(items))
}

fn element_setitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = receiver(vm, args, "__setitem__")?;
    let element = element_of(vm, &target, "__setitem__")?;
    let (index, value) = wrapper_pair(vm, rest)?;

    assign_subscript(vm, element, &index, Some(value))?;

    Ok(Value::None)
}

fn element_delitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = receiver(vm, args, "__delitem__")?;
    let element = element_of(vm, &target, "__delitem__")?;
    let index = wrapper_operand(vm, rest)?;

    assign_subscript(vm, element, &index, None)?;

    Ok(Value::None)
}

/// `Element.__setitem__`; `None` deletes.
fn assign_subscript(vm: &Vm, element: &Element, index: &Value, value: Option<Value>) -> PyResult<()> {
    if let Some(position) = index_operand(vm, index)? {
        return assign_item(vm, element, position, value);
    }

    let Some(slice) = vm.slice_of(index) else {
        return Err(vm.type_error("element indices must be integers"));
    };

    assign_slice(vm, element, &slice, value)
}

/// Replaces or deletes one child.
fn assign_item(vm: &Vm, element: &Element, position: i64, value: Option<Value>) -> PyResult<()> {
    let removed = {
        let mut extra = element.extra.borrow_mut();
        let Some(extra) = extra.as_mut() else {
            return Err(vm.raise(ExceptionKind::IndexError, "child assignment index out of range"));
        };
        let length = extra.children.len();
        let position = if position < 0 { position + length as i64 } else { position };
        let Some(position) = usize::try_from(position).ok().filter(|position| *position < length) else {
            return Err(vm.raise(ExceptionKind::IndexError, "child assignment index out of range"));
        };

        match value {
            Some(value) => extra.children.get_mut(position).map(|slot| std::mem::replace(slot, value)),
            None => Some(extra.children.remove(position)),
        }
    };
    drop(removed);

    Ok(())
}

/// The slice branch of `Element.__setitem__`.
fn assign_slice(vm: &Vm, element: &Element, slice: &SliceData, value: Option<Value>) -> PyResult<()> {
    element.with_extra(|_| ());
    let length = element.length();
    let indices = vm.slice_indices(slice, length)?;
    let positions: Vec<usize> = indices.positions().collect();

    let replacement = match &value {
        Some(value) => sequence_items(vm, value)?,
        None => Vec::new(),
    };
    if indices.step != 1 && replacement.len() != positions.len() {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("attempt to assign sequence of size {} to extended slice of size {}", replacement.len(), positions.len())));
    }

    // The bounds are computed before Python code ran.
    if element.extra_length() != Some(length) {
        return Err(vm.halt_unsupported("Element slice assignment while Python code changes the element's children"));
    }
    // With `start > stop` and a nonempty replacement CPython corrupts the
    // children.
    if indices.step == 1 && indices.start > indices.stop && !replacement.is_empty() {
        return Err(vm.halt_unsupported("Element slice assignment with start after stop: 2.7.12 corrupts the children"));
    }

    let replaced = element.with_extra(|extra| {
        if indices.step == 1 {
            let start = indices.start.clamp(0, length as i64) as usize;
            let end = (start + positions.len()).min(extra.children.len());
            return extra.children.splice(start..end, replacement).collect::<Vec<Value>>();
        }

        let mut replaced = Vec::with_capacity(positions.len());
        for (position, item) in positions.into_iter().zip(replacement) {
            if let Some(slot) = extra.children.get_mut(position) {
                replaced.push(std::mem::replace(slot, item));
            }
        }
        replaced
    });
    drop(replaced);

    Ok(())
}

fn tree_builder_of<'a>(vm: &Vm, value: &'a Value, method: &str) -> PyResult<&'a TreeBuilder> {
    native_data::<TreeBuilder>(value).ok_or_else(|| vm.type_error(&format!("descriptor '{method}' requires a 'TreeBuilder' object but received a '{}'", vm.type_name(value))))
}

fn tree_builder_getattribute(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, name) = hook_target(vm, args, "__getattribute__")?;
    tree_builder_of(vm, &target, "__getattribute__")?;

    find_method(vm, &target, &name, &TREE_BUILDER_METHODS).ok_or_else(|| attribute_error(vm, &name))
}

fn tree_builder_data(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let builder = this::<TreeBuilder>(vm, &args, "TreeBuilder", "data")?;
    let ([data], []) = method_args::<1, 0>(vm, &args, "data")?;

    builder.handle_data(vm, data)
}

fn tree_builder_start(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let builder = this::<TreeBuilder>(vm, &args, "TreeBuilder", "start")?;
    let ([tag], [attrib]) = method_args::<1, 1>(vm, &args, "start")?;

    builder.handle_start(vm, tag, attrib.unwrap_or(Value::None))
}

fn tree_builder_end(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let builder = this::<TreeBuilder>(vm, &args, "TreeBuilder", "end")?;
    method_args::<1, 0>(vm, &args, "end")?;

    builder.handle_end(vm)
}

fn tree_builder_xml(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<TreeBuilder>(vm, &args, "TreeBuilder", "xml")?;
    method_args::<2, 0>(vm, &args, "xml")?;

    Ok(Value::None)
}

fn tree_builder_close(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let builder = this::<TreeBuilder>(vm, &args, "TreeBuilder", "close")?;
    method_args::<0, 0>(vm, &args, "close")?;

    Ok(builder.done())
}

fn xml_parser_of<'a>(vm: &Vm, value: &'a Value, method: &str) -> PyResult<&'a XmlParser> {
    native_data::<XmlParser>(value).ok_or_else(|| vm.type_error(&format!("descriptor '{method}' requires a 'XMLParser' object but received a '{}'", vm.type_name(value))))
}

fn xml_parser_getattribute(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, name) = hook_target(vm, args, "__getattribute__")?;
    let parser = xml_parser_of(vm, &target, "__getattribute__")?;

    if let Some(method) = find_method(vm, &target, &name, &XML_PARSER_METHODS) {
        return Ok(method);
    }

    match name.as_slice() {
        b"entity" => Ok(Value::Object(Rc::clone(&parser.entity))),
        b"target" => Ok(parser.target.clone()),
        b"version" => {
            let (major, minor, micro) = EXPAT_VERSION_INFO;
            Ok(Value::str(&format!("Expat {major}.{minor}.{micro}")))
        }
        _ => Err(attribute_error(vm, &name)),
    }
}

fn xml_parser_feed(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let parser = this::<XmlParser>(vm, &args, "XMLParser", "feed")?;
    let ([data], []) = method_args::<1, 0>(vm, &args, "feed")?;
    halt_on_unknown(&data, "XMLParser.feed data")?;
    let data = read_buffer(vm, "feed", 1, &data)?;

    parser.parse(vm, data.as_bytes(), false)?;

    Ok(Value::None)
}

/// The tree builder's root, or what the target's `close` returns.
fn xml_parser_close(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let parser = this::<XmlParser>(vm, &args, "XMLParser", "close")?;
    method_args::<0, 0>(vm, &args, "close")?;

    parser.parse(vm, b"", true)?;

    if let Some(builder) = parser.tree_builder() {
        return Ok(builder.done());
    }
    match &parser.methods.close {
        Some(close) => vm.call(close, CallArgs::default()),
        None => Ok(Value::None),
    }
}

/// Reads the file in 64 KiB chunks until `read` returns something other
/// than a non-empty `str`.
fn xml_parser_parse(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let parser = this::<XmlParser>(vm, &args, "XMLParser", "_parse")?;
    let ([file], []) = method_args::<1, 0>(vm, &args, "_parse")?;

    let read = vm.getattr_str(&file, "read")?;
    loop {
        let buffer = vm.call1(&read, Value::Int(64 * 1024))?;
        halt_on_unknown(&buffer, "XMLParser._parse read result")?;
        let Value::Str(chunk) = &buffer else {
            break;
        };
        if chunk.as_bytes().is_empty() {
            break;
        }
        if i32::try_from(chunk.as_bytes().len()).is_err() {
            return Err(vm.raise(ExceptionKind::OverflowError, "size does not fit in an int"));
        }
        parser.parse(vm, chunk.as_bytes(), false)?;
    }

    parser.parse(vm, b"", true)?;

    Ok(parser.tree_builder().map_or(Value::None, TreeBuilder::done))
}

/// Collects `(event, node)` pairs from a tree builder target into
/// `events`.
fn xml_parser_setevents(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let parser = this::<XmlParser>(vm, &args, "XMLParser", "_setevents")?;
    let ([events], [event_set]) = method_args::<1, 1>(vm, &args, "_setevents")?;
    halt_on_unknown(&events, "_setevents list")?;
    if !events.as_object().is_some_and(|object| matches!(object.payload, Payload::List(_))) {
        return Err(wrong_argument(vm, "_setevents", 1, "list", &events));
    }

    let Some(builder) = parser.tree_builder() else {
        return Err(vm.type_error("event handling only supported for cElementTree.Treebuilder targets"));
    };
    *builder.events.borrow_mut() = Some(Events::new(events));

    let event_set = event_set.unwrap_or(Value::None);
    if event_set.is_none() {
        set_event(builder, Event::End, Value::str("end"));
        return Ok(Value::None);
    }
    halt_on_unknown(&event_set, "_setevents event tuple")?;
    let invalid = || vm.type_error("invalid event tuple");
    let Some(names) = vm.as_tuple(&event_set) else {
        return Err(invalid());
    };

    for item in names.iter() {
        halt_on_unknown(item, "_setevents event name")?;
        let Some(name) = vm.as_str_bytes(item) else {
            return Err(invalid());
        };
        let event = match until_nul(name.as_bytes()) {
            b"start" => Event::Start,
            b"end" => Event::End,
            b"start-ns" => Event::StartNs,
            b"end-ns" => Event::EndNs,
            other => {
                let mut message = b"unknown event '".to_vec();
                message.extend_from_slice(other);
                message.push(b'\'');
                let class = Rc::clone(vm.types().exception(ExceptionKind::ValueError));
                return Err(vm.raise_string(&class, Value::Str(PyBytes::new(message))));
            }
        };
        set_event(builder, event, item.clone());
        if matches!(event, Event::StartNs | Event::EndNs) {
            parser.install_namespace_handlers(vm)?;
        }
    }

    Ok(Value::None)
}

fn set_event(builder: &TreeBuilder, event: Event, action: Value) {
    let mut events = builder.events.borrow_mut();
    let Some(events) = events.as_mut() else {
        return;
    };

    let slot = match event {
        Event::Start => &mut events.start,
        Event::End => &mut events.end,
        Event::StartNs => &mut events.start_ns,
        Event::EndNs => &mut events.end_ns,
    };
    *slot = Some(action);
}

/// Imports `primary`, or `fallback` when `primary` raises ImportError.
fn import_either(vm: &Vm, primary: &str, fallback: &str) -> PyResult<Value> {
    match vm.import_module(primary) {
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::ImportError) => vm.import_module(fallback),
        result => result,
    }
}

/// Binds `args` as a Python function with parameters `names` does, the
/// last `defaults` of which default to `None`. `implicit` counts a receiver
/// the caller does not pass in `args` but that the error messages include.
fn bind_parameters<const N: usize>(vm: &Vm, args: CallArgs, function: &str, names: [&str; N], defaults: usize, implicit: usize) -> PyResult<[Value; N]> {
    if args.keyword_dict.is_some() {
        return Err(vm.type_error(&format!("{function}() keywords must be strings")));
    }

    let given = args.positional.len() + implicit;
    let plural = |count: usize| if count == 1 { "" } else { "s" };
    if given > N {
        let bound = if defaults == 0 { "exactly" } else { "at most" };
        return Err(vm.type_error(&format!("{function}() takes {bound} {N} argument{} ({given} given)", plural(N))));
    }

    // The implicit receiver is already bound, so a keyword naming it is a
    // second value.
    let mut slots: [Option<Value>; N] = std::array::from_fn(|index| (index < implicit).then_some(Value::None));
    for (slot, value) in slots.iter_mut().skip(implicit).zip(args.positional) {
        *slot = Some(value);
    }
    for (keyword, value) in args.keywords {
        let Some(index) = names.iter().position(|name| name.as_bytes() == keyword.as_bytes()) else {
            return Err(vm.type_error(&format!("{function}() got an unexpected keyword argument '{}'", keyword.to_string_lossy())));
        };
        if slots[index].is_some() {
            return Err(vm.type_error(&format!("{function}() got multiple values for keyword argument '{}'", keyword.to_string_lossy())));
        }
        slots[index] = Some(value);
    }

    let required = N - defaults;
    if slots.iter().take(required).skip(implicit).any(Option::is_none) {
        let bound = if defaults == 0 { "exactly" } else { "at least" };
        return Err(vm.type_error(&format!("{function}() takes {bound} {required} argument{} ({given} given)", plural(required))));
    }

    Ok(slots.map(|slot| slot.unwrap_or(Value::None)))
}

/// A new-style class defined in `__builtin__` whose methods are native.
fn new_python_class(vm: &Vm, name: &str, base: Value, methods: &[(&'static str, NativeFn)]) -> PyResult<Value> {
    let namespace = vm.new_dict();
    vm.dict_set_str(&namespace, "__module__", Value::str("__builtin__"))?;
    let class = vm.type_new(&vm.types().type_, &Value::str(name), &Value::tuple(vec![base]), &Value::Object(namespace))?;
    let Value::Object(class_object) = &class else {
        return Err(vm.type_error("class creation did not produce a class"));
    };

    for &(method_name, function) in methods {
        let entry = new_class_entry(vm, class_object, method_name, function, NativeBinding::Method);
        vm.setattr_str(&class, method_name, entry)?;
    }

    Ok(class)
}

/// An instance of a classic class `name` whose `__call__` and `__cmp__` are
/// native functions that do not receive the instance.
fn new_proxy(vm: &Vm, name: &str, call: NativeFn, compare: NativeFn) -> PyResult<Value> {
    let dict = vm.new_dict();
    vm.dict_set_str(&dict, "__module__", Value::str("__builtin__"))?;
    vm.dict_set_str(&dict, "__call__", vm.new_native_function("__call__", call))?;
    vm.dict_set_str(&dict, "__cmp__", vm.new_native_function("__cmp__", compare))?;
    let class = vm.new_classic_class(&Value::str(name), Vec::new(), dict)?;

    vm.call(&class, CallArgs::default())
}

/// An element whose tag is `tag`, as `Element(tag)` creates.
fn tagged_element(vm: &Vm, tag: Value) -> PyResult<Value> {
    element_factory(vm, CallArgs::new(vec![tag]))
}

/// `Comment(text=None)`: an element tagged `ElementTree.Comment`.
fn comment_call(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [_, text] = bind_parameters(vm, args, "__call__", ["self", "text"], 1, 1)?;
    let element = tagged_element(vm, helper(vm, &glue(vm).comment_tag, "Comment")?)?;
    vm.setattr_str(&element, "text", text)?;

    Ok(element)
}

/// `PI(target, text=None)`: an element tagged `ElementTree.PI` whose text
/// is the target, followed by a space and `text` when `text` is true.
fn pi_call(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [_, target, text] = bind_parameters(vm, args, "__call__", ["self", "target", "text"], 1, 1)?;
    let element = tagged_element(vm, helper(vm, &glue(vm).pi_tag, "PI")?)?;
    vm.setattr_str(&element, "text", target.clone())?;
    if vm.truthy(&text, "PI text")? {
        let spaced = vm.binary_op(BinaryOp::Add, &target, &Value::str(" "))?;
        vm.setattr_str(&element, "text", vm.binary_op(BinaryOp::Add, &spaced, &text)?)?;
    }

    Ok(element)
}

/// `cmp` of the proxied tag with `other`.
fn proxy_compare(vm: &Vm, args: CallArgs, tag: Value) -> PyResult<Value> {
    let [_, other] = bind_parameters(vm, args, "__cmp__", ["self", "other"], 0, 1)?;
    let cmp = vm.builtin_value("cmp")?;

    vm.call(&cmp, CallArgs::new(vec![tag, other]))
}

fn comment_compare(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    proxy_compare(vm, args, helper(vm, &glue(vm).comment_tag, "Comment")?)
}

fn pi_compare(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    proxy_compare(vm, args, helper(vm, &glue(vm).pi_tag, "PI")?)
}

/// `copyelement(elem)`: rebuilds a reduced element, which is its argument.
fn copy_element_function(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [element] = bind_parameters(vm, args, "copyelement", ["elem"], 0, 0)?;

    Ok(element)
}

/// An `XMLParser` with a fresh `TreeBuilder` target.
fn tree_builder_parser(vm: &Vm) -> PyResult<Value> {
    xml_parser_factory(vm, CallArgs::new(vec![new_tree_builder(vm)?]))
}

/// `XML(text)` and `fromstring(text)`: the root element of the document.
fn xml_function(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [text] = bind_parameters(vm, args, "XML", ["text"], 0, 0)?;

    parse_text(vm, text)
}

fn parse_text(vm: &Vm, text: Value) -> PyResult<Value> {
    let parser = tree_builder_parser(vm)?;
    xml_parser_feed(vm, CallArgs::new(vec![parser.clone(), text]))?;

    xml_parser_close(vm, CallArgs::new(vec![parser]))
}

/// `XMLID(text)`: the root element and a dict mapping each true `id`
/// attribute to the last element in document order that carries it.
fn xml_id(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [text] = bind_parameters(vm, args, "XMLID", ["text"], 0, 0)?;
    let root = parse_text(vm, text)?;

    let ids = vm.new_dict();
    let elements = vm.call_method(&root, "iter", Vec::new())?;
    for element in vm.collect(&elements)? {
        let id = vm.call_method(&element, "get", vec![Value::str("id")])?;
        if vm.truthy(&id, "XMLID id")? {
            vm.dict_set(&ids, id, element)?;
        }
    }

    Ok(Value::tuple(vec![root, Value::Object(ids)]))
}

/// `parse(source, parser=None)`: a new `ElementTree` whose `parse` read
/// `source`.
fn parse_function(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [source, parser] = bind_parameters(vm, args, "parse", ["source", "parser"], 1, 0)?;
    let tree_class = helper(vm, &glue(vm).tree_class, "ElementTree")?;

    let tree = vm.call(&tree_class, CallArgs::default())?;
    vm.call_method(&tree, "parse", vec![source, parser])?;

    Ok(tree)
}

/// `source`, or the file `open(source, "rb")` returns when `source` has no
/// `read` attribute. The file is not closed afterwards.
fn readable_source(vm: &Vm, source: Value) -> PyResult<(Value, bool)> {
    let hasattr = vm.builtin_value("hasattr")?;
    let readable = vm.call(&hasattr, CallArgs::new(vec![source.clone(), Value::str("read")]))?;
    if vm.truthy(&readable, "hasattr")? {
        return Ok((source, false));
    }

    let open = vm.builtin_value("open")?;
    let file = vm.call(&open, CallArgs::new(vec![source, Value::str("rb")]))?;

    Ok((file, true))
}

/// Read size of `ElementTree.parse` with a caller's parser.
const TREE_PARSE_CHUNK: i64 = 64 * 1024;

/// `ElementTree.parse(self, source, parser=None)`. The default parser
/// reads the file itself; another parser is fed each chunk `read` returns
/// until one is false, then closed.
fn tree_parse(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [tree, source, parser] = bind_parameters(vm, args, "parse", ["self", "source", "parser"], 1, 0)?;
    let (source, _) = readable_source(vm, source)?;

    let root = if parser.is_none() {
        let parser = tree_builder_parser(vm)?;
        xml_parser_parse(vm, CallArgs::new(vec![parser, source]))?
    } else {
        loop {
            let data = vm.call_method(&source, "read", vec![Value::Int(TREE_PARSE_CHUNK)])?;
            if !vm.truthy(&data, "ElementTree.parse data")? {
                break;
            }
            vm.call_method(&parser, "feed", vec![data])?;
        }
        vm.call_method(&parser, "close", Vec::new())?
    };
    vm.setattr_str(&tree, "_root", root.clone())?;

    Ok(root)
}

/// Read size of `iterparse`.
const ITERPARSE_CHUNK: i64 = 16 * 1024;

/// `iterparse.__init__(self, file, events=None)`.
fn iterparse_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [iterator, file, event_set] = bind_parameters(vm, args, "__init__", ["self", "file", "events"], 1, 0)?;
    let (file, close_file) = readable_source(vm, file)?;

    let events = vm.new_list(Vec::new());
    vm.setattr_str(&iterator, "_file", file)?;
    vm.setattr_str(&iterator, "_events", events.clone())?;
    vm.setattr_str(&iterator, "_index", Value::Int(0))?;
    vm.setattr_str(&iterator, "_error", Value::None)?;
    vm.setattr_str(&iterator, "root", Value::None)?;
    vm.setattr_str(&iterator, "_root", Value::None)?;

    let parser = tree_builder_parser(vm)?;
    xml_parser_setevents(vm, CallArgs::new(vec![parser.clone(), events, event_set]))?;
    vm.setattr_str(&iterator, "_parser", parser)?;
    vm.setattr_str(&iterator, "_close_file", Value::Bool(close_file))?;

    Ok(Value::None)
}

fn iterparse_iter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [iterator] = bind_parameters(vm, args, "__iter__", ["self"], 0, 0)?;

    Ok(iterator)
}

/// `iterparse.next(self)`: the next buffered event. When the buffer is
/// used up, a deferred parse error is raised, or the next chunk is parsed,
/// or at the end of the file the parser is closed and `root` is set. A
/// parse error while feeding is deferred until the events before it are
/// consumed.
fn iterparse_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [iterator] = bind_parameters(vm, args, "next", ["self"], 0, 0)?;

    loop {
        let events = vm.getattr_str(&iterator, "_events")?;
        let index = vm.getattr_str(&iterator, "_index")?;
        match vm.getitem(&events, &index) {
            Ok(item) => {
                vm.setattr_str(&iterator, "_index", vm.binary_op(BinaryOp::Add, &index, &Value::Int(1))?)?;
                return Ok(item);
            }
            Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::IndexError) => {}
            Err(signal) => return Err(signal),
        }

        let error = vm.getattr_str(&iterator, "_error")?;
        if vm.truthy(&error, "iterparse error")? {
            vm.setattr_str(&iterator, "_error", Value::None)?;
            return Err(Signal::Raise(error));
        }

        let parser = vm.getattr_str(&iterator, "_parser")?;
        if parser.is_none() {
            vm.setattr_str(&iterator, "root", vm.getattr_str(&iterator, "_root")?)?;
            if vm.truthy(&vm.getattr_str(&iterator, "_close_file")?, "iterparse close_file")? {
                vm.call_method(&vm.getattr_str(&iterator, "_file")?, "close", Vec::new())?;
            }
            return Err(stop_iteration(vm));
        }

        vm.delitem(&events, &vm.new_slice(Value::None, Value::None, Value::None))?;
        vm.setattr_str(&iterator, "_index", Value::Int(0))?;
        let data = vm.call_method(&vm.getattr_str(&iterator, "_file")?, "read", vec![Value::Int(ITERPARSE_CHUNK)])?;
        if vm.truthy(&data, "iterparse data")? {
            match vm.call_method(&parser, "feed", vec![data]) {
                Ok(_) => {}
                Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::SyntaxError) => vm.setattr_str(&iterator, "_error", error)?,
                Err(signal) => return Err(signal),
            }
        } else {
            let root = vm.call_method(&parser, "close", Vec::new())?;
            vm.setattr_str(&iterator, "_root", root)?;
            vm.setattr_str(&iterator, "_parser", Value::None)?;
        }
    }
}

const ELEMENT_WALK_KEY: &str = "_elementtree.iterator";

/// What an element walk yields.
#[derive(Clone, Copy)]
enum WalkKind {
    /// Each element in document order whose tag equals the walk's tag.
    Elements,
    /// Each true `text` and `tail` in document order, without the tail of
    /// the starting element.
    Text,
}

struct WalkFrame {
    element: Value,
    next_child: i64,
}

/// The lazy iterator `Element.iter` and `Element.itertext` return. Each
/// step reads children by index, so changes to the children during the
/// walk are seen.
struct ElementWalk {
    kind: WalkKind,
    /// The tag elements must equal, or `None` for every element.
    tag: RefCell<Option<Value>>,
    start: RefCell<Option<Value>>,
    stack: RefCell<Vec<WalkFrame>>,
}

impl_native_data!(ElementWalk, "iterator");

fn new_walk(vm: &Vm, element: Value, kind: WalkKind, tag: Option<Value>) -> PyResult<Value> {
    let class = native_type(vm, ELEMENT_WALK_KEY, create_walk_type)?;
    let walk = ElementWalk { kind, tag: RefCell::new(tag), start: RefCell::new(Some(element)), stack: RefCell::new(Vec::new()) };

    Ok(new_native_object(vm, &class, walk))
}

fn create_walk_type(vm: &Vm) -> PyResult<ObjectRef> {
    const METHODS: &[MethodSpec] = &[method("__iter__", walk_iter), method("next", walk_next)];

    new_final_type(vm, TypeSpec { name: "iterator", module: "_elementtree", base: None, layout: Layout::Native, instance_dict: false, methods: METHODS })
}

fn walk_iter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<ElementWalk>(vm, &args, "iterator", "__iter__")?;
    method_args::<0, 0>(vm, &args, "__iter__")?;

    Ok(receiver_of(&args))
}

fn walk_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let walk = this::<ElementWalk>(vm, &args, "iterator", "next")?;
    method_args::<0, 0>(vm, &args, "next")?;

    match walk.step(vm) {
        Ok(Some(item)) => Ok(item),
        Ok(None) => Err(stop_iteration(vm)),
        Err(signal) => {
            walk.finish();
            Err(signal)
        }
    }
}

/// `element[index]`, or `None` past the last child.
fn child_at(vm: &Vm, element: &Value, index: i64) -> PyResult<Option<Value>> {
    match vm.getitem(element, &Value::Int(index)) {
        Ok(child) => Ok(Some(child)),
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::IndexError) => Ok(None),
        Err(signal) => Err(signal),
    }
}

/// The attribute `name` of `element` when it is true.
fn true_attribute(vm: &Vm, element: &Value, name: &str) -> PyResult<Option<Value>> {
    let value = vm.getattr_str(element, name)?;

    Ok(vm.truthy(&value, "itertext")?.then_some(value))
}

impl ElementWalk {
    /// The value the element yields on entry, if any.
    fn enter(&self, vm: &Vm, element: &Value) -> PyResult<Option<Value>> {
        match self.kind {
            WalkKind::Elements => {
                let tag = self.tag.borrow().clone();
                let Some(tag) = tag else {
                    return Ok(Some(element.clone()));
                };
                let element_tag = vm.getattr_str(element, "tag")?;
                Ok(vm.equals(&element_tag, &tag)?.then(|| element.clone()))
            }
            WalkKind::Text => true_attribute(vm, element, "text"),
        }
    }

    /// The value the element yields when its children are done, if any.
    fn leave(&self, vm: &Vm, element: &Value, is_start: bool) -> PyResult<Option<Value>> {
        match self.kind {
            WalkKind::Text if !is_start => true_attribute(vm, element, "tail"),
            _ => Ok(None),
        }
    }

    /// The next value, or `None` when the walk is done. The stack is not
    /// borrowed across calls into Python code.
    fn step(&self, vm: &Vm) -> PyResult<Option<Value>> {
        let start = self.start.borrow_mut().take();
        if let Some(element) = start {
            // A `"*"` tag matches every element; it is compared when the
            // walk starts, not when the iterator is created.
            let tag = self.tag.borrow().clone();
            if let Some(tag) = tag
                && vm.equals(&tag, &Value::str("*"))?
            {
                *self.tag.borrow_mut() = None;
            }
            self.stack.borrow_mut().push(WalkFrame { element: element.clone(), next_child: 0 });
            if let Some(item) = self.enter(vm, &element)? {
                return Ok(Some(item));
            }
        }

        loop {
            let Some((element, index)) = self.stack.borrow().last().map(|frame| (frame.element.clone(), frame.next_child)) else {
                return Ok(None);
            };

            match child_at(vm, &element, index)? {
                Some(child) => {
                    // A cyclic tree would otherwise grow the stack forever.
                    if self.stack.borrow().len() >= vm.recursion_limit() {
                        return Err(vm.raise(ExceptionKind::RuntimeError, "maximum recursion depth exceeded"));
                    }
                    let mut stack = self.stack.borrow_mut();
                    if let Some(frame) = stack.last_mut() {
                        frame.next_child = index + 1;
                    }
                    stack.push(WalkFrame { element: child.clone(), next_child: 0 });
                    drop(stack);
                    if let Some(item) = self.enter(vm, &child)? {
                        return Ok(Some(item));
                    }
                }
                None => {
                    let is_start = {
                        let mut stack = self.stack.borrow_mut();
                        stack.pop();
                        stack.is_empty()
                    };
                    if let Some(item) = self.leave(vm, &element, is_start)? {
                        return Ok(Some(item));
                    }
                }
            }
        }
    }

    /// Ends the walk, as an exception ends a generator.
    fn finish(&self) {
        self.start.borrow_mut().take();
        self.stack.borrow_mut().clear();
    }
}
