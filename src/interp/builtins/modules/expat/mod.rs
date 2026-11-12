//! An XML 1.0 parser whose observable behavior (handler calls, positions,
//! error codes, incremental parsing) matches the expat 2.1.1 library that
//! CPython 2.7.12 bundles, as configured there: namespace support, DTD
//! support, 1024 bytes of retained input context and UTF-8 output.

mod chars;
mod content;
mod dtd;
mod encoding;
mod grammar;
mod parser;
mod prolog;
mod scan;
mod values;

use std::ops::Range;

pub use parser::Parser;

/// The library's error numbers. Clients see the numeric value.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum ErrorCode {
    None = 0,
    NoMemory = 1,
    Syntax = 2,
    NoElements = 3,
    InvalidToken = 4,
    UnclosedToken = 5,
    PartialChar = 6,
    TagMismatch = 7,
    DuplicateAttribute = 8,
    JunkAfterDocElement = 9,
    ParamEntityRef = 10,
    UndefinedEntity = 11,
    RecursiveEntityRef = 12,
    AsyncEntity = 13,
    BadCharRef = 14,
    BinaryEntityRef = 15,
    AttributeExternalEntityRef = 16,
    MisplacedXmlPi = 17,
    UnknownEncoding = 18,
    IncorrectEncoding = 19,
    UnclosedCdataSection = 20,
    ExternalEntityHandling = 21,
    NotStandalone = 22,
    UnexpectedState = 23,
    EntityDeclaredInPe = 24,
    FeatureRequiresXmlDtd = 25,
    CantChangeFeatureOnceParsing = 26,
    UnboundPrefix = 27,
    UndeclaringPrefix = 28,
    IncompletePe = 29,
    XmlDecl = 30,
    TextDecl = 31,
    PublicId = 32,
    Suspended = 33,
    NotSuspended = 34,
    Aborted = 35,
    Finished = 36,
    SuspendPe = 37,
    ReservedPrefixXml = 38,
    ReservedPrefixXmlns = 39,
    ReservedNamespaceUri = 40,
}

/// The message for an error number; `None` for numbers without one.
pub fn error_string(code: i32) -> Option<&'static str> {
    let message = match code {
        1 => "out of memory",
        2 => "syntax error",
        3 => "no element found",
        4 => "not well-formed (invalid token)",
        5 => "unclosed token",
        6 => "partial character",
        7 => "mismatched tag",
        8 => "duplicate attribute",
        9 => "junk after document element",
        10 => "illegal parameter entity reference",
        11 => "undefined entity",
        12 => "recursive entity reference",
        13 => "asynchronous entity",
        14 => "reference to invalid character number",
        15 => "reference to binary entity",
        16 => "reference to external entity in attribute",
        17 => "XML or text declaration not at start of entity",
        18 => "unknown encoding",
        19 => "encoding specified in XML declaration is incorrect",
        20 => "unclosed CDATA section",
        21 => "error in processing external entity reference",
        22 => "document is not standalone",
        23 => "unexpected parser state - please send a bug report",
        24 => "entity declared in parameter entity",
        25 => "requested feature requires XML_DTD support in Expat",
        26 => "cannot change setting once parsing has begun",
        27 => "unbound prefix",
        28 => "must not undeclare prefix",
        29 => "incomplete markup in parameter entity",
        30 => "XML declaration not well-formed",
        31 => "text declaration not well-formed",
        32 => "illegal character(s) in public id",
        33 => "parser suspended",
        34 => "parser not suspended",
        35 => "parsing aborted",
        36 => "parsing finished",
        37 => "cannot suspend in external parameter entity",
        38 => "reserved prefix (xml) must not be undeclared or bound to another namespace name",
        39 => "reserved prefix (xmlns) must not be declared or undeclared",
        40 => "prefix must not be bound to one of the reserved namespace names",
        _ => return None,
    };

    Some(message)
}

/// The library version string.
pub fn expat_version() -> &'static str {
    "expat_2.1.1"
}

/// The library version as (major, minor, micro).
pub const EXPAT_VERSION_INFO: (i32, i32, i32) = (2, 1, 1);

/// The compile-time features the library reports, in its order.
pub fn feature_list() -> &'static [(&'static str, i64)] {
    &[("sizeof(XML_Char)", 1), ("sizeof(XML_LChar)", 1), ("XML_DTD", 0), ("XML_CONTEXT_BYTES", 1024), ("XML_NS", 0)]
}

/// The result of a parse call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum Status {
    Error = 0,
    Ok = 1,
    Suspended = 2,
}

/// When parameter entities, including the external DTD subset, are read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum ParamEntityParsing {
    Never = 0,
    UnlessStandalone = 1,
    Always = 2,
}

/// The kind of a content model node.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum ContentType {
    Empty = 1,
    Any = 2,
    Mixed = 3,
    Name = 4,
    Choice = 5,
    Seq = 6,
}

/// The repetition suffix of a content model node.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum ContentQuant {
    None = 0,
    Opt = 1,
    Rep = 2,
    Plus = 3,
}

/// A node of an element declaration's content model.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ContentModel {
    pub kind: ContentType,
    pub quant: ContentQuant,
    pub name: Option<Vec<u8>>,
    pub children: Vec<ContentModel>,
}

/// Chosen by the application; stored in a handler slot and handed back on each call
/// so the application knows which of its callbacks was installed (e.g. Default vs
/// DefaultExpand, or a no-op character data handler).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CallbackId(pub u16);

/// The handlers an application can install.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandlerSlot {
    StartElement,
    EndElement,
    CharacterData,
    ProcessingInstruction,
    Comment,
    StartCdataSection,
    EndCdataSection,
    Default,
    StartDoctypeDecl,
    EndDoctypeDecl,
    EntityDecl,
    UnparsedEntityDecl,
    NotationDecl,
    StartNamespaceDecl,
    EndNamespaceDecl,
    NotStandalone,
    ExternalEntityRef,
    SkippedEntity,
    UnknownEncoding,
    XmlDecl,
    ElementDecl,
    AttlistDecl,
}

impl HandlerSlot {
    const COUNT: usize = 22;
}

/// A start tag's attributes as alternating names and values; the attributes
/// given in the tag come before those supplied by ATTLIST defaults.
#[derive(Clone, Copy)]
pub struct Attributes<'a> {
    bytes: &'a [u8],
    spans: &'a [Range<usize>],
}

impl<'a> Attributes<'a> {
    pub(super) fn new(bytes: &'a [u8], spans: &'a [Range<usize>]) -> Self {
        Self { bytes, spans }
    }

    /// The number of strings, two per attribute.
    pub fn len(&self) -> usize {
        self.spans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&'a [u8]> {
        let span = self.spans.get(index)?;

        self.bytes.get(span.clone())
    }
}

/// The `context` argument of the external entity reference handler.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntityContext<'a> {
    /// No context: a parameter entity or the external DTD subset.
    Absent,
    Text(&'a [u8]),
    /// The context lists two or more namespace bindings, or two or more open
    /// entities. The library emits those in the iteration order of a hash table
    /// seeded per process, so the text depends on the host run.
    HostOrdered,
}

/// The application side of a parse. Each method corresponds to a handler slot and
/// runs only while that slot holds a callback.
pub trait Callbacks {
    fn start_element(&mut self, parser: &mut Parser, callback: CallbackId, name: &[u8], attributes: Attributes<'_>);
    fn end_element(&mut self, parser: &mut Parser, callback: CallbackId, name: &[u8]);
    fn character_data(&mut self, parser: &mut Parser, callback: CallbackId, data: &[u8]);
    fn processing_instruction(&mut self, parser: &mut Parser, callback: CallbackId, target: &[u8], data: &[u8]);
    fn comment(&mut self, parser: &mut Parser, callback: CallbackId, data: &[u8]);
    fn start_cdata_section(&mut self, parser: &mut Parser, callback: CallbackId);
    fn end_cdata_section(&mut self, parser: &mut Parser, callback: CallbackId);
    fn default(&mut self, parser: &mut Parser, callback: CallbackId, data: &[u8]);
    /// `name` is None when the handler was installed after the DOCTYPE name was read.
    fn start_doctype_decl(
        &mut self,
        parser: &mut Parser,
        callback: CallbackId,
        name: Option<&[u8]>,
        system_id: Option<&[u8]>,
        public_id: Option<&[u8]>,
        has_internal_subset: bool,
    );
    fn end_doctype_decl(&mut self, parser: &mut Parser, callback: CallbackId);
    #[allow(clippy::too_many_arguments)]
    fn entity_decl(
        &mut self,
        parser: &mut Parser,
        callback: CallbackId,
        name: &[u8],
        is_parameter_entity: bool,
        value: Option<&[u8]>,
        base: Option<&[u8]>,
        system_id: Option<&[u8]>,
        public_id: Option<&[u8]>,
        notation_name: Option<&[u8]>,
    );
    #[allow(clippy::too_many_arguments)]
    fn unparsed_entity_decl(
        &mut self,
        parser: &mut Parser,
        callback: CallbackId,
        name: &[u8],
        base: Option<&[u8]>,
        system_id: &[u8],
        public_id: Option<&[u8]>,
        notation_name: &[u8],
    );
    fn notation_decl(
        &mut self,
        parser: &mut Parser,
        callback: CallbackId,
        name: &[u8],
        base: Option<&[u8]>,
        system_id: Option<&[u8]>,
        public_id: Option<&[u8]>,
    );
    fn start_namespace_decl(&mut self, parser: &mut Parser, callback: CallbackId, prefix: Option<&[u8]>, uri: Option<&[u8]>);
    fn end_namespace_decl(&mut self, parser: &mut Parser, callback: CallbackId, prefix: Option<&[u8]>);
    /// False rejects the document as not standalone.
    fn not_standalone(&mut self, parser: &mut Parser, callback: CallbackId) -> bool;
    /// False reports a failure to process the entity.
    fn external_entity_ref(
        &mut self,
        parser: &mut Parser,
        callback: CallbackId,
        context: EntityContext<'_>,
        base: Option<&[u8]>,
        system_id: Option<&[u8]>,
        public_id: Option<&[u8]>,
    ) -> bool;
    fn skipped_entity(&mut self, parser: &mut Parser, callback: CallbackId, name: &[u8], is_parameter_entity: bool);
    /// The code point of each byte value (-1 for bytes that cannot occur), or
    /// `None` when the encoding is not supported.
    fn unknown_encoding(&mut self, parser: &mut Parser, callback: CallbackId, name: &[u8]) -> Option<[i32; 256]>;
    fn xml_decl(&mut self, parser: &mut Parser, callback: CallbackId, version: Option<&[u8]>, encoding: Option<&[u8]>, standalone: i32);
    fn element_decl(&mut self, parser: &mut Parser, callback: CallbackId, name: &[u8], model: ContentModel);
    #[allow(clippy::too_many_arguments)]
    fn attlist_decl(
        &mut self,
        parser: &mut Parser,
        callback: CallbackId,
        element_name: &[u8],
        attribute_name: &[u8],
        attribute_type: &[u8],
        default: Option<&[u8]>,
        is_required: bool,
    );
}
