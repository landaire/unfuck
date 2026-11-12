//! The prolog processor: the XML declaration, the DOCTYPE declaration with
//! its internal and external subsets, parameter entities, and the parsers
//! for external parameter entities.

use std::mem;
use std::rc::Rc;

use super::Callbacks;
use super::ContentModel;
use super::ContentQuant;
use super::ContentType;
use super::ErrorCode;
use super::HandlerSlot;
use super::ParamEntityParsing;
use super::dtd::DeclaredAttribute;
use super::dtd::EXTERNAL_SUBSET;
use super::dtd::Entity;
use super::encoding::Encoding;
use super::encoding::KnownEncoding;
use super::encoding::push_utf8;
use super::grammar::Quant;
use super::grammar::Role;
use super::parser::Parser;
use super::parser::Phase;
use super::parser::Stage;
use super::scan::Scan;
use super::scan::Scanner;
use super::scan::Tok;
use super::values::char_ref_value;
use super::values::normalize_newlines;
use super::values::normalize_public_id;
use super::values::predefined_entity;
use super::values::public_id_error;

/// Where the tokens being processed come from.
#[derive(Clone, Debug)]
pub(super) enum Src {
    /// The parser's input buffer, in the input encoding.
    Document,
    /// Replacement text of an internal entity, in UTF-8.
    Text(Rc<[u8]>),
}

/// The DOCTYPE system identifier as recorded: the literal when the start
/// handler wants it, or only the fact that one was given.
#[derive(Clone, Debug)]
enum DoctypeSystem {
    Literal(Vec<u8>),
    Given,
}

/// One node of a content model under construction.
#[derive(Clone, Debug)]
struct ModelNode {
    kind: ContentType,
    quant: ContentQuant,
    name: Option<Vec<u8>>,
    children: Vec<usize>,
}

/// A parameter entity whose replacement text is being processed.
#[derive(Clone, Debug)]
struct PeFrame {
    name: Rc<[u8]>,
    text: Rc<[u8]>,
    pos: usize,
    /// Referenced between declarations, so the text must hold whole declarations.
    between_decl: bool,
}

/// What the prolog processor remembers between tokens.
#[derive(Clone, Debug, Default)]
pub(super) struct PrologState {
    doctype_name: Option<Vec<u8>>,
    doctype_system: Option<DoctypeSystem>,
    doctype_public: Option<Vec<u8>>,

    /// The entity being declared: whether it is a parameter entity and its
    /// name. `None` when the declaration repeats an earlier one.
    decl_entity: Option<(bool, Rc<[u8]>)>,

    notation_name: Option<Vec<u8>>,
    notation_public: Option<Vec<u8>>,

    attlist_element: Option<Rc<[u8]>>,
    attribute_name: Option<Rc<[u8]>>,
    attribute_type: Option<Vec<u8>>,
    attribute_is_cdata: bool,
    attribute_is_id: bool,

    element_name: Option<Rc<[u8]>>,
    in_element_decl: bool,
    model: Vec<ModelNode>,
    /// Indices of the open groups of the content model.
    groups: Vec<usize>,
    /// The connector seen in each open group: `,`, `|` or none yet.
    connectors: Vec<u8>,

    frames: Vec<PeFrame>,
    /// Inside a parameter entity's replacement text.
    in_internal_pe: bool,
}

impl PrologState {
    pub(super) fn in_internal_pe(&self) -> bool {
        self.in_internal_pe
    }
}

/// The UTF-8 decoder for entity replacement text.
const UTF8: Encoding = Encoding::Utf8;

/// The parts of a parsed XML or text declaration.
struct XmlDeclParts {
    version: Option<(usize, usize)>,
    encoding: Option<(usize, usize)>,
    standalone: i32,
}

impl Parser {
    /// The bytes and decoder of a source.
    pub(super) fn src_parts<'a>(&'a self, src: &'a Src) -> (&'a [u8], &'a Encoding) {
        match src {
            Src::Document => (&self.data, &self.encoding),
            Src::Text(text) => (text, &UTF8),
        }
    }

    pub(super) fn scanner<'a>(&'a self, src: &'a Src) -> Scanner<'a> {
        let (buf, enc) = self.src_parts(src);

        Scanner::new(buf, buf.len(), enc, self.ns_separator.is_some())
    }

    /// `src[start..end]` converted to UTF-8.
    pub(super) fn utf8(&self, src: &Src, start: usize, end: usize) -> Vec<u8> {
        let (buf, enc) = self.src_parts(src);
        let mut out = Vec::with_capacity(end.saturating_sub(start));
        enc.append_utf8(buf, start, end, &mut out);

        out
    }

    fn unit(&self, src: &Src) -> usize {
        self.src_parts(src).1.unit()
    }

    /// Hands `src[start..end]` to the default handler, converted in pieces
    /// when the input is not UTF-8. Document text moves the event pointer.
    pub(super) fn report_default(&mut self, callbacks: &mut dyn Callbacks, src: &Src, start: usize, end: usize) {
        let Some(callback) = self.handler(HandlerSlot::Default) else {
            return;
        };
        let (buf, enc) = self.src_parts(src);
        if enc.is_utf8() {
            let text = buf.get(start..end).unwrap_or_default().to_vec();
            callbacks.default(self, callback, &text);
            return;
        }

        let mut pos = start;
        loop {
            let (buf, enc) = self.src_parts(src);
            let piece_end = enc.piece_end(buf, pos, end);
            let mut text = Vec::new();
            enc.append_utf8(buf, pos, piece_end, &mut text);
            if matches!(src, Src::Document) {
                self.event_end = Some(piece_end);
            }
            let Some(callback) = self.handler(HandlerSlot::Default) else {
                return;
            };
            callbacks.default(self, callback, &text);
            if matches!(src, Src::Document) {
                self.event = Some(piece_end);
            }
            pos = piece_end;
            if pos >= end {
                return;
            }
        }
    }

    /// Reports a processing instruction token `start..end`.
    pub(super) fn report_pi(&mut self, callbacks: &mut dyn Callbacks, src: &Src, start: usize, end: usize) {
        let Some(callback) = self.handler(HandlerSlot::ProcessingInstruction) else {
            if self.has(HandlerSlot::Default) {
                self.report_default(callbacks, src, start, end);
            }
            return;
        };

        let unit = self.unit(src);
        let scanner = self.scanner(src);
        let target_start = start + 2 * unit;
        let target_end = scanner.name_end(target_start);
        let data_start = scanner.skip_space(target_end).min(end - 2 * unit);
        let target = self.utf8(src, target_start, target_end);
        let mut data = self.utf8(src, data_start, end - 2 * unit);
        normalize_newlines(&mut data);

        callbacks.processing_instruction(self, callback, &target, &data);
    }

    /// Reports a comment token `start..end`.
    pub(super) fn report_comment(&mut self, callbacks: &mut dyn Callbacks, src: &Src, start: usize, end: usize) {
        let Some(callback) = self.handler(HandlerSlot::Comment) else {
            if self.has(HandlerSlot::Default) {
                self.report_default(callbacks, src, start, end);
            }
            return;
        };

        let unit = self.unit(src);
        let mut data = self.utf8(src, start + 4 * unit, end - 3 * unit);
        normalize_newlines(&mut data);

        callbacks.comment(self, callback, &data);
    }

    /// Sets up the input encoding for a document or entity: a known protocol
    /// encoding, or the unknown encoding handler for any other name.
    fn init_encoding(&mut self, callbacks: &mut dyn Callbacks) -> Result<(), ErrorCode> {
        self.init_protocol_encoding(callbacks)
    }

    /// Detects the encoding from the first bytes and scans the first token,
    /// in the prolog or in content. `Bom` covers a byte order mark.
    pub(super) fn first_scan(&mut self, start: usize, content: bool) -> Scan {
        let protocol = self.protocol_encoding.as_deref().and_then(KnownEncoding::from_name);
        let scan_with = |parser: &mut Parser, encoding: Encoding| {
            parser.encoding = encoding;
            parser.encoding_fixed = true;
            let scanner = parser.scanner(&Src::Document);
            if content { scanner.content(start) } else { scanner.prolog(start) }
        };
        let default = protocol.map_or(Encoding::Utf8, KnownEncoding::encoding);

        let available = self.data.len() - start;
        if available == 0 {
            return Scan { tok: Tok::Empty, next: start, open: false };
        }
        let first = self.data[start];
        if available == 1 {
            if protocol.is_some_and(KnownEncoding::is_utf16) {
                return Scan { tok: Tok::Partial, next: start, open: false };
            }
            let possible_bom = matches!(first, 0xFE | 0xFF | 0xEF) && !(protocol == Some(KnownEncoding::Latin1) && content);
            if possible_bom || matches!(first, 0x00 | 0x3C) {
                return Scan { tok: Tok::Partial, next: start, open: false };
            }
            return scan_with(self, default);
        }

        let second = self.data[start + 1];
        let latin1_content = protocol == Some(KnownEncoding::Latin1) && content;
        match (first, second) {
            (0xFE, 0xFF) if !latin1_content => {
                self.encoding = Encoding::Utf16 { big_endian: true };
                self.encoding_fixed = true;
                return Scan { tok: Tok::Bom, next: start + 2, open: false };
            }
            (0xFF, 0xFE) if !latin1_content => {
                self.encoding = Encoding::Utf16 { big_endian: false };
                self.encoding_fixed = true;
                return Scan { tok: Tok::Bom, next: start + 2, open: false };
            }
            (0x3C, 0x00) => {
                let keep = content && matches!(protocol, Some(KnownEncoding::Utf16Be | KnownEncoding::Utf16));
                if !keep {
                    return scan_with(self, Encoding::Utf16 { big_endian: false });
                }
            }
            (0xEF, 0xBB) => {
                let keep = content && matches!(protocol, Some(KnownEncoding::Latin1 | KnownEncoding::Utf16Be | KnownEncoding::Utf16Le | KnownEncoding::Utf16));
                if !keep {
                    if available == 2 {
                        return Scan { tok: Tok::Partial, next: start, open: false };
                    }
                    if self.data[start + 2] == 0xBF {
                        self.encoding = Encoding::Utf8;
                        self.encoding_fixed = true;
                        return Scan { tok: Tok::Bom, next: start + 3, open: false };
                    }
                }
            }
            (0x00, _) => {
                let keep = content && protocol == Some(KnownEncoding::Utf16Le);
                if !keep {
                    return scan_with(self, Encoding::Utf16 { big_endian: true });
                }
            }
            (_, 0x00) if !content => return scan_with(self, Encoding::Utf16 { big_endian: false }),
            _ => {}
        }

        scan_with(self, default)
    }

    /// The scan of the next prolog token of the document entity, settling the
    /// encoding first when it is still open.
    fn document_prolog_scan(&mut self, pos: usize) -> Scan {
        if !self.encoding_fixed {
            return self.first_scan(pos, false);
        }

        self.scanner(&Src::Document).prolog(pos)
    }

    pub(super) fn run_prolog_start(&mut self, callbacks: &mut dyn Callbacks, start: usize) -> Result<(), ErrorCode> {
        self.init_encoding(callbacks)?;
        self.stage = Stage::Prolog;

        self.run_prolog(callbacks, start)
    }

    pub(super) fn run_prolog(&mut self, callbacks: &mut dyn Callbacks, start: usize) -> Result<(), ErrorCode> {
        let scan = self.document_prolog_scan(start);

        self.prolog_loop(callbacks, start, scan)
    }

    /// The document-level prolog loop, starting with the token `scan` at `s`.
    fn prolog_loop(&mut self, callbacks: &mut dyn Callbacks, mut s: usize, mut scan: Scan) -> Result<(), ErrorCode> {
        let have_more = !self.final_buffer;
        loop {
            self.event = Some(s);
            self.event_end = Some(scan.next);

            let complete = !scan.open && !matches!(scan.tok, Tok::Invalid | Tok::Partial | Tok::PartialChar | Tok::Empty);
            if !complete {
                if have_more && scan.tok != Tok::Invalid {
                    self.ptr = s;
                    return Ok(());
                }
                match scan.tok {
                    Tok::Invalid => {
                        self.event = Some(scan.next);
                        return Err(ErrorCode::InvalidToken);
                    }
                    Tok::Partial => return Err(ErrorCode::UnclosedToken),
                    Tok::PartialChar => return Err(ErrorCode::PartialChar),
                    Tok::Empty => {
                        if !self.is_param_entity {
                            return Err(ErrorCode::NoElements);
                        }
                        if self.grammar.role(Tok::Empty, b"") == Role::Error {
                            return Err(ErrorCode::IncompletePe);
                        }
                        self.ptr = s;
                        return Ok(());
                    }
                    // At the end of the input a token that could have grown is complete.
                    _ => {}
                }
            }

            let next = match self.prolog_token(callbacks, &Src::Document, scan.tok, s, scan.next)? {
                PrologStep::Continue => scan.next,
                PrologStep::IgnoreDone(after) => after,
                PrologStep::Handover => return Ok(()),
            };
            self.run_pe_frames(callbacks)?;

            match self.phase {
                Phase::Suspended => {
                    self.ptr = next;
                    return Ok(());
                }
                Phase::Finished => return Err(ErrorCode::Aborted),
                Phase::Initialized | Phase::Parsing => {}
            }

            s = next;
            scan = self.scanner(&Src::Document).prolog(s);
        }
    }

    /// Processes the replacement text of the parameter entities pushed by a
    /// reference, nested references included.
    fn run_pe_frames(&mut self, callbacks: &mut dyn Callbacks) -> Result<(), ErrorCode> {
        while let Some(frame) = self.prolog.frames.last_mut() {
            let src = Src::Text(Rc::clone(&frame.text));
            let pos = frame.pos;
            let between_decl = frame.between_decl;
            let scan = self.scanner(&src).prolog(pos);

            match scan.tok {
                Tok::Invalid => return Err(ErrorCode::InvalidToken),
                Tok::Partial => return Err(ErrorCode::UnclosedToken),
                Tok::PartialChar => return Err(ErrorCode::PartialChar),
                Tok::Empty => {
                    if between_decl && self.grammar.role(Tok::Empty, b"") == Role::Error {
                        return Err(ErrorCode::IncompletePe);
                    }
                    self.close_pe_frame();
                    continue;
                }
                _ => {}
            }

            // The frame moves on before the token runs, which may push another frame.
            if let Some(frame) = self.prolog.frames.last_mut() {
                frame.pos = scan.next;
            }
            self.prolog.in_internal_pe = true;
            let step = self.prolog_token(callbacks, &src, scan.tok, pos, scan.next);
            self.prolog.in_internal_pe = !self.prolog.frames.is_empty();
            if let PrologStep::IgnoreDone(after) = step?
                && let Some(frame) = self.prolog.frames.last_mut()
            {
                frame.pos = after;
            }

            match self.phase {
                Phase::Suspended => return Ok(()),
                Phase::Finished => return Err(ErrorCode::Aborted),
                Phase::Initialized | Phase::Parsing => {}
            }
        }
        self.prolog.in_internal_pe = false;

        Ok(())
    }

    fn close_pe_frame(&mut self) {
        let Some(frame) = self.prolog.frames.pop() else {
            return;
        };
        if let Some(entity) = self.dtd.borrow_mut().parameter.get_mut(&frame.name) {
            entity.open = false;
        }
        self.prolog.in_internal_pe = !self.prolog.frames.is_empty();
    }

    /// Handles one prolog token `start..next` from `src`.
    fn prolog_token(&mut self, callbacks: &mut dyn Callbacks, src: &Src, tok: Tok, start: usize, next: usize) -> Result<PrologStep, ErrorCode> {
        let unit = self.unit(src);
        let text = match tok {
            Tok::DeclOpen => self.utf8(src, start + 2 * unit, next),
            Tok::PoundName => self.utf8(src, start + unit, next),
            Tok::Name | Tok::PrefixedName => self.utf8(src, start, next),
            _ => Vec::new(),
        };
        let role = self.grammar.role(tok, &text);
        let is_document = matches!(src, Src::Document);
        let mut handle_default = true;

        match role {
            Role::Error => {
                return Err(match tok {
                    Tok::ParamEntityRef => ErrorCode::ParamEntityRef,
                    Tok::XmlDecl => ErrorCode::MisplacedXmlPi,
                    _ => ErrorCode::Syntax,
                });
            }
            Role::None => {
                if tok == Tok::Bom {
                    handle_default = false;
                }
            }
            Role::XmlDecl | Role::TextDecl => {
                self.process_xml_decl(callbacks, role == Role::TextDecl, start, next)?;
                handle_default = false;
            }
            Role::InstanceStart => {
                self.read_foreign_dtd(callbacks)?;
                self.stage = if self.is_child { Stage::ExternalEntityContent } else { Stage::Content };
                self.run_content(callbacks, start)?;
                return Ok(PrologStep::Handover);
            }
            Role::Pi => {
                self.report_pi(callbacks, src, start, next);
                handle_default = false;
            }
            Role::Comment => {
                self.report_comment(callbacks, src, start, next);
                handle_default = false;
            }

            Role::DoctypeNone => {
                if self.has(HandlerSlot::StartDoctypeDecl) {
                    handle_default = false;
                }
            }
            Role::DoctypeName => {
                if self.has(HandlerSlot::StartDoctypeDecl) {
                    self.prolog.doctype_name = Some(text);
                    self.prolog.doctype_public = None;
                    handle_default = false;
                }
                self.prolog.doctype_system = None;
            }
            Role::DoctypeInternalSubset => {
                if let Some(callback) = self.handler(HandlerSlot::StartDoctypeDecl) {
                    let name = self.prolog.doctype_name.take();
                    let system = self.doctype_system_text();
                    let public = self.prolog.doctype_public.clone();
                    callbacks.start_doctype_decl(self, callback, name.as_deref(), system.as_deref(), public.as_deref(), true);
                    handle_default = false;
                }
            }
            Role::DoctypePublicId => {
                self.use_foreign_dtd = false;
                self.prolog.decl_entity = Some((true, Rc::from(EXTERNAL_SUBSET)));
                self.dtd.borrow_mut().parameter.entry(Rc::from(EXTERNAL_SUBSET)).or_default();
                let literal = self.check_public_id(src, start, next)?;
                if self.has(HandlerSlot::StartDoctypeDecl) {
                    self.prolog.doctype_public = Some(literal.clone());
                    handle_default = false;
                }
                self.set_entity_public_id(literal, &mut handle_default);
            }
            Role::DoctypeSystemId => {
                if self.has(HandlerSlot::StartDoctypeDecl) {
                    self.prolog.doctype_system = Some(DoctypeSystem::Literal(self.utf8(src, start + unit, next - unit)));
                    handle_default = false;
                } else {
                    self.prolog.doctype_system = Some(DoctypeSystem::Given);
                }
                // An external subset may declare anything, so references to
                // undeclared entities are no longer errors.
                self.dtd.borrow_mut().has_param_entity_refs = true;
                let standalone = self.dtd.borrow().standalone;
                if !standalone && self.param_entity_parsing == ParamEntityParsing::Never && !self.call_not_standalone(callbacks) {
                    return Err(ErrorCode::NotStandalone);
                }
                if self.prolog.decl_entity.is_none() {
                    let mut dtd = self.dtd.borrow_mut();
                    let entity = dtd.parameter.entry(Rc::from(EXTERNAL_SUBSET)).or_default();
                    entity.public_id = None;
                    drop(dtd);
                    self.prolog.decl_entity = Some((true, Rc::from(EXTERNAL_SUBSET)));
                }
                self.set_entity_system_id(src, start, next, &mut handle_default);
            }
            Role::DoctypeClose => {
                if let Some(name) = self.prolog.doctype_name.take()
                    && let Some(callback) = self.handler(HandlerSlot::StartDoctypeDecl)
                {
                    let system = self.doctype_system_text();
                    let public = self.prolog.doctype_public.clone();
                    callbacks.start_doctype_decl(self, callback, Some(&name), system.as_deref(), public.as_deref(), false);
                    handle_default = false;
                }
                if self.prolog.doctype_system.is_some() || self.use_foreign_dtd {
                    self.read_external_subset(callbacks, self.prolog.doctype_system.is_none())?;
                }
                self.use_foreign_dtd = false;
                if let Some(callback) = self.handler(HandlerSlot::EndDoctypeDecl) {
                    callbacks.end_doctype_decl(self, callback);
                    handle_default = false;
                }
            }

            Role::EntityNone => {
                if self.dtd.borrow().keep_processing && self.has(HandlerSlot::EntityDecl) {
                    handle_default = false;
                }
            }
            Role::GeneralEntityName | Role::ParamEntityName => {
                let is_param = role == Role::ParamEntityName;
                self.prolog.decl_entity = None;
                let name = self.utf8(src, start, next);
                if !is_param && predefined_entity(&name).is_some() {
                    // Redeclaring a predefined entity is ignored.
                } else if self.dtd.borrow().keep_processing {
                    let name: Rc<[u8]> = Rc::from(name);
                    let is_internal = !(self.is_child || self.prolog.in_internal_pe);
                    let mut dtd = self.dtd.borrow_mut();
                    let entities = dtd.entities_mut(is_param);
                    if !entities.contains_key(&name) {
                        entities.insert(Rc::clone(&name), Entity { is_internal, ..Entity::default() });
                        drop(dtd);
                        self.prolog.decl_entity = Some((is_param, name));
                        if self.has(HandlerSlot::EntityDecl) {
                            handle_default = false;
                        }
                    }
                }
            }
            Role::EntityValue => {
                if self.dtd.borrow().keep_processing {
                    let result = self.store_entity_value(callbacks, src, start + unit, next - unit);
                    let value = mem::take(&mut self.dtd.borrow_mut().entity_value);
                    if let Some((is_param, name)) = self.prolog.decl_entity.clone() {
                        let value: Rc<[u8]> = Rc::from(value);
                        if let Some(entity) = self.dtd.borrow_mut().entities_mut(is_param).get_mut(&name) {
                            entity.text = Some(Rc::clone(&value));
                        }
                        if let Some(callback) = self.handler(HandlerSlot::EntityDecl) {
                            if is_document {
                                self.event_end = Some(start);
                            }
                            let base = self.base.clone();
                            callbacks.entity_decl(self, callback, &name, is_param, Some(&value), base.as_deref(), None, None, None);
                            handle_default = false;
                        }
                    }
                    result?;
                }
            }
            Role::EntityPublicId => {
                let literal = self.check_public_id(src, start, next)?;
                self.set_entity_public_id(literal, &mut handle_default);
            }
            Role::EntitySystemId => self.set_entity_system_id(src, start, next, &mut handle_default),
            Role::EntityComplete => {
                if self.dtd.borrow().keep_processing
                    && let Some((is_param, name)) = self.prolog.decl_entity.clone()
                    && let Some(callback) = self.handler(HandlerSlot::EntityDecl)
                {
                    let entity = self.dtd.borrow().entities(is_param).get(&name).cloned().unwrap_or_default();
                    if is_document {
                        self.event_end = Some(start);
                    }
                    callbacks.entity_decl(
                        self,
                        callback,
                        &name,
                        is_param,
                        None,
                        entity.base.as_deref(),
                        entity.system_id.as_deref(),
                        entity.public_id.as_deref(),
                        None,
                    );
                    handle_default = false;
                }
            }
            Role::EntityNotationName => {
                if self.dtd.borrow().keep_processing
                    && let Some((is_param, name)) = self.prolog.decl_entity.clone()
                {
                    let notation: Rc<[u8]> = Rc::from(self.utf8(src, start, next));
                    let entity = {
                        let mut dtd = self.dtd.borrow_mut();
                        let entity = dtd.entities_mut(is_param).entry(Rc::clone(&name)).or_default();
                        entity.notation = Some(Rc::clone(&notation));
                        entity.clone()
                    };
                    if is_document {
                        self.event_end = Some(start);
                    }
                    if let Some(callback) = self.handler(HandlerSlot::UnparsedEntityDecl) {
                        callbacks.unparsed_entity_decl(
                            self,
                            callback,
                            &name,
                            entity.base.as_deref(),
                            entity.system_id.as_deref().unwrap_or_default(),
                            entity.public_id.as_deref(),
                            &notation,
                        );
                        handle_default = false;
                    } else if let Some(callback) = self.handler(HandlerSlot::EntityDecl) {
                        callbacks.entity_decl(
                            self,
                            callback,
                            &name,
                            false,
                            None,
                            entity.base.as_deref(),
                            entity.system_id.as_deref(),
                            entity.public_id.as_deref(),
                            Some(&notation),
                        );
                        handle_default = false;
                    }
                }
            }

            Role::NotationNone => {
                if self.has(HandlerSlot::NotationDecl) {
                    handle_default = false;
                }
            }
            Role::NotationName => {
                self.prolog.notation_public = None;
                self.prolog.notation_name = None;
                if self.has(HandlerSlot::NotationDecl) {
                    self.prolog.notation_name = Some(self.utf8(src, start, next));
                    handle_default = false;
                }
            }
            Role::NotationPublicId => {
                let literal = self.check_public_id(src, start, next)?;
                if self.prolog.notation_name.is_some() {
                    self.prolog.notation_public = Some(literal);
                    handle_default = false;
                }
            }
            Role::NotationSystemId => {
                if let Some(name) = self.prolog.notation_name.clone()
                    && let Some(callback) = self.handler(HandlerSlot::NotationDecl)
                {
                    let system = self.utf8(src, start + unit, next - unit);
                    let public = self.prolog.notation_public.clone();
                    let base = self.base.clone();
                    if is_document {
                        self.event_end = Some(start);
                    }
                    callbacks.notation_decl(self, callback, &name, base.as_deref(), Some(&system), public.as_deref());
                    handle_default = false;
                }
            }
            Role::NotationNoSystemId => {
                if let Some(public) = self.prolog.notation_public.clone()
                    && let Some(name) = self.prolog.notation_name.clone()
                    && let Some(callback) = self.handler(HandlerSlot::NotationDecl)
                {
                    let base = self.base.clone();
                    if is_document {
                        self.event_end = Some(start);
                    }
                    callbacks.notation_decl(self, callback, &name, base.as_deref(), None, Some(&public));
                    handle_default = false;
                }
            }

            Role::AttlistNone => self.attlist_default(&mut handle_default),
            Role::AttlistElementName => {
                self.prolog.attlist_element = Some(Rc::from(self.utf8(src, start, next)));
                self.attlist_default(&mut handle_default);
            }
            Role::AttributeName => {
                self.prolog.attribute_name = Some(Rc::from(self.utf8(src, start, next)));
                self.prolog.attribute_is_cdata = false;
                self.prolog.attribute_type = None;
                self.prolog.attribute_is_id = false;
                self.attlist_default(&mut handle_default);
            }
            Role::AttributeType(kind) => {
                self.prolog.attribute_is_cdata = kind == super::grammar::AttributeType::Cdata;
                self.prolog.attribute_is_id = kind == super::grammar::AttributeType::Id;
                self.prolog.attribute_type = Some(kind.keyword().to_vec());
                self.attlist_default(&mut handle_default);
            }
            Role::AttributeEnumValue | Role::AttributeNotationValue => {
                if self.dtd.borrow().keep_processing && self.has(HandlerSlot::AttlistDecl) {
                    let value = self.utf8(src, start, next);
                    let opener: &[u8] = if role == Role::AttributeEnumValue { b"(" } else { b"NOTATION(" };
                    let kind = self.prolog.attribute_type.get_or_insert_with(Vec::new);
                    if kind.is_empty() {
                        kind.extend_from_slice(opener);
                    } else {
                        kind.push(b'|');
                    }
                    kind.extend_from_slice(&value);
                    handle_default = false;
                }
            }
            Role::ImpliedAttributeValue | Role::RequiredAttributeValue => {
                if self.dtd.borrow().keep_processing {
                    self.define_attribute(None);
                    if self.attlist_report(callbacks, is_document, start, None, role == Role::RequiredAttributeValue) {
                        handle_default = false;
                    }
                }
            }
            Role::DefaultAttributeValue | Role::FixedAttributeValue => {
                if self.dtd.borrow().keep_processing {
                    let is_cdata = self.prolog.attribute_is_cdata;
                    let mut value = Vec::new();
                    self.normalize_attribute_value(src, is_cdata, start + unit, next - unit, true, &mut value)?;
                    let value: Rc<[u8]> = Rc::from(value);
                    self.define_attribute(Some(Rc::clone(&value)));
                    if self.attlist_report(callbacks, is_document, start, Some(&value), role == Role::FixedAttributeValue) {
                        handle_default = false;
                    }
                }
            }

            Role::ElementNone => {
                if self.has(HandlerSlot::ElementDecl) {
                    handle_default = false;
                }
            }
            Role::ElementName => {
                if self.has(HandlerSlot::ElementDecl) {
                    self.prolog.element_name = Some(Rc::from(self.utf8(src, start, next)));
                    self.prolog.model.clear();
                    self.prolog.groups.clear();
                    self.prolog.in_element_decl = true;
                    handle_default = false;
                }
            }
            Role::ContentAny | Role::ContentEmpty => {
                if self.prolog.in_element_decl {
                    if let Some(callback) = self.handler(HandlerSlot::ElementDecl) {
                        let kind = if role == Role::ContentAny { ContentType::Any } else { ContentType::Empty };
                        let model = ContentModel { kind, quant: ContentQuant::None, name: None, children: Vec::new() };
                        let name = self.prolog.element_name.clone().unwrap_or_else(|| Rc::from(&b""[..]));
                        if is_document {
                            self.event_end = Some(start);
                        }
                        callbacks.element_decl(self, callback, &name, model);
                        handle_default = false;
                    }
                    self.prolog.in_element_decl = false;
                }
            }
            Role::ContentPcdata => {
                if self.prolog.in_element_decl {
                    if let Some(&group) = self.prolog.groups.last()
                        && let Some(node) = self.prolog.model.get_mut(group)
                    {
                        node.kind = ContentType::Mixed;
                    }
                    if self.has(HandlerSlot::ElementDecl) {
                        handle_default = false;
                    }
                }
            }
            Role::ContentElement(quant) => {
                if self.prolog.in_element_decl {
                    let name_end = if quant == Quant::One { next } else { next - unit };
                    let name = self.utf8(src, start, name_end);
                    let index = self.add_model_node(ContentType::Name);
                    if let Some(node) = self.prolog.model.get_mut(index) {
                        node.quant = content_quant(quant);
                        node.name = Some(name);
                    }
                    if self.has(HandlerSlot::ElementDecl) {
                        handle_default = false;
                    }
                }
            }
            Role::GroupOpen => {
                let level = self.grammar.level;
                if self.prolog.connectors.len() <= level {
                    self.prolog.connectors.resize(level + 1, 0);
                }
                self.prolog.connectors[level] = 0;
                if self.prolog.in_element_decl {
                    let index = self.add_model_node(ContentType::Seq);
                    self.prolog.groups.push(index);
                    if self.has(HandlerSlot::ElementDecl) {
                        handle_default = false;
                    }
                }
            }
            Role::GroupSequence => {
                let level = self.grammar.level;
                if self.prolog.connectors.get(level) == Some(&b'|') {
                    return Err(ErrorCode::Syntax);
                }
                if let Some(connector) = self.prolog.connectors.get_mut(level) {
                    *connector = b',';
                }
                if self.prolog.in_element_decl && self.has(HandlerSlot::ElementDecl) {
                    handle_default = false;
                }
            }
            Role::GroupChoice => {
                let level = self.grammar.level;
                let connector = self.prolog.connectors.get(level).copied().unwrap_or(0);
                if connector == b',' {
                    return Err(ErrorCode::Syntax);
                }
                if self.prolog.in_element_decl && connector != b'|' {
                    let group = self.prolog.groups.last().copied();
                    if let Some(node) = group.and_then(|group| self.prolog.model.get_mut(group))
                        && node.kind != ContentType::Mixed
                    {
                        node.kind = ContentType::Choice;
                        if self.has(HandlerSlot::ElementDecl) {
                            handle_default = false;
                        }
                    }
                }
                if let Some(connector) = self.prolog.connectors.get_mut(level) {
                    *connector = b'|';
                }
            }
            Role::GroupClose(quant) => {
                if self.prolog.in_element_decl {
                    if self.has(HandlerSlot::ElementDecl) {
                        handle_default = false;
                    }
                    if let Some(group) = self.prolog.groups.pop()
                        && let Some(node) = self.prolog.model.get_mut(group)
                    {
                        node.quant = content_quant(quant);
                    }
                    if self.prolog.groups.is_empty() {
                        if !handle_default && let Some(callback) = self.handler(HandlerSlot::ElementDecl) {
                            let model = self.build_model();
                            let name = self.prolog.element_name.clone().unwrap_or_else(|| Rc::from(&b""[..]));
                            if is_document {
                                self.event_end = Some(start);
                            }
                            callbacks.element_decl(self, callback, &name, model);
                        }
                        self.prolog.in_element_decl = false;
                    }
                }
            }

            Role::ParamEntityRef | Role::InnerParamEntityRef => {
                let name = self.utf8(src, start + unit, next - unit);
                if self.reference_param_entity(callbacks, &name, role == Role::ParamEntityRef)? {
                    handle_default = false;
                }
            }
            Role::IncludeSection => {}
            Role::IgnoreSection => {
                if self.has(HandlerSlot::Default) {
                    self.report_default(callbacks, src, start, next);
                }
                return self.skip_ignore_section(callbacks, src, next);
            }
        }

        if handle_default && self.has(HandlerSlot::Default) {
            self.report_default(callbacks, src, start, next);
        }

        Ok(PrologStep::Continue)
    }

    /// The system identifier for the start doctype handler.
    fn doctype_system_text(&self) -> Option<Vec<u8>> {
        match &self.prolog.doctype_system {
            Some(DoctypeSystem::Literal(text)) => Some(text.clone()),
            Some(DoctypeSystem::Given) => Some(EXTERNAL_SUBSET.to_vec()),
            None => None,
        }
    }

    /// Checks a public identifier literal and returns its normalized text.
    fn check_public_id(&mut self, src: &Src, start: usize, next: usize) -> Result<Vec<u8>, ErrorCode> {
        let unit = self.unit(src);
        let (buf, enc) = self.src_parts(src);
        if let Some(bad) = public_id_error(buf, start + unit, next - unit, enc) {
            if matches!(src, Src::Document) {
                self.event = Some(bad);
            }
            return Err(ErrorCode::PublicId);
        }

        Ok(normalize_public_id(&self.utf8(src, start + unit, next - unit)))
    }

    fn set_entity_public_id(&mut self, literal: Vec<u8>, handle_default: &mut bool) {
        if !self.dtd.borrow().keep_processing {
            return;
        }
        let Some((is_param, name)) = self.prolog.decl_entity.clone() else {
            return;
        };

        if let Some(entity) = self.dtd.borrow_mut().entities_mut(is_param).get_mut(&name) {
            entity.public_id = Some(Rc::from(literal));
        }
        if self.has(HandlerSlot::EntityDecl) {
            *handle_default = false;
        }
    }

    fn set_entity_system_id(&mut self, src: &Src, start: usize, next: usize, handle_default: &mut bool) {
        if !self.dtd.borrow().keep_processing {
            return;
        }
        let Some((is_param, name)) = self.prolog.decl_entity.clone() else {
            return;
        };

        let unit = self.unit(src);
        let system: Rc<[u8]> = Rc::from(self.utf8(src, start + unit, next - unit));
        let base = self.base.clone();
        if let Some(entity) = self.dtd.borrow_mut().entities_mut(is_param).get_mut(&name) {
            entity.system_id = Some(system);
            entity.base = base;
        }
        if self.has(HandlerSlot::EntityDecl) {
            *handle_default = false;
        }
    }

    fn call_not_standalone(&mut self, callbacks: &mut dyn Callbacks) -> bool {
        let Some(callback) = self.handler(HandlerSlot::NotStandalone) else {
            return true;
        };

        callbacks.not_standalone(self, callback)
    }

    /// Reads the external subset through the external entity handler at the
    /// end of the DOCTYPE declaration. `foreign_only` marks a foreign DTD
    /// standing in for a subset the document did not name.
    fn read_external_subset(&mut self, callbacks: &mut dyn Callbacks, foreign_only: bool) -> Result<(), ErrorCode> {
        let had_refs = self.dtd.borrow().has_param_entity_refs;
        self.dtd.borrow_mut().has_param_entity_refs = true;
        if self.param_entity_parsing == ParamEntityParsing::Never {
            return Ok(());
        }
        let Some(callback) = self.handler(HandlerSlot::ExternalEntityRef) else {
            return Ok(());
        };

        let entity = {
            let mut dtd = self.dtd.borrow_mut();
            let entity = dtd.parameter.entry(Rc::from(EXTERNAL_SUBSET)).or_default();
            if self.use_foreign_dtd {
                entity.base = self.base.clone();
            }
            dtd.param_entity_read = false;
            dtd.parameter.get(EXTERNAL_SUBSET).cloned().unwrap_or_default()
        };
        let accepted = callbacks.external_entity_ref(
            self,
            callback,
            super::EntityContext::Absent,
            entity.base.as_deref(),
            entity.system_id.as_deref(),
            entity.public_id.as_deref(),
        );
        if !accepted {
            return Err(ErrorCode::ExternalEntityHandling);
        }

        let (read, standalone) = {
            let dtd = self.dtd.borrow();
            (dtd.param_entity_read, dtd.standalone)
        };
        if read {
            if !standalone && !self.call_not_standalone(callbacks) {
                return Err(ErrorCode::NotStandalone);
            }
        } else if foreign_only {
            self.dtd.borrow_mut().has_param_entity_refs = had_refs;
        }

        Ok(())
    }

    /// Reads the foreign DTD when the document element starts without a
    /// DOCTYPE declaration.
    fn read_foreign_dtd(&mut self, callbacks: &mut dyn Callbacks) -> Result<(), ErrorCode> {
        if !self.use_foreign_dtd {
            return Ok(());
        }

        self.read_external_subset(callbacks, true)
    }

    /// Clears `handle_default` when ATTLIST declarations are reported.
    fn attlist_default(&self, handle_default: &mut bool) {
        if self.dtd.borrow().keep_processing && self.has(HandlerSlot::AttlistDecl) {
            *handle_default = false;
        }
    }

    /// Records the attribute just declared for the ATTLIST element.
    fn define_attribute(&mut self, value: Option<Rc<[u8]>>) {
        let (Some(element), Some(name)) = (self.prolog.attlist_element.clone(), self.prolog.attribute_name.clone()) else {
            return;
        };

        let ns_reserved = self.ns_separator.is_some() && is_xmlns_attribute(&name);
        let attribute = DeclaredAttribute { name, value, is_cdata: self.prolog.attribute_is_cdata };
        let is_id = self.prolog.attribute_is_id;
        self.dtd.borrow_mut().element_mut(&element).declare(attribute, is_id, ns_reserved);
    }

    /// Calls the ATTLIST handler for the attribute just declared; true when it ran.
    fn attlist_report(&mut self, callbacks: &mut dyn Callbacks, is_document: bool, start: usize, value: Option<&[u8]>, flag: bool) -> bool {
        let Some(callback) = self.handler(HandlerSlot::AttlistDecl) else {
            return false;
        };
        let Some(mut kind) = self.prolog.attribute_type.clone() else {
            return false;
        };

        if kind.first() == Some(&b'(') || (kind.first() == Some(&b'N') && kind.get(1) == Some(&b'O')) {
            kind.push(b')');
        }
        let element = self.prolog.attlist_element.clone().unwrap_or_else(|| Rc::from(&b""[..]));
        let name = self.prolog.attribute_name.clone().unwrap_or_else(|| Rc::from(&b""[..]));
        if is_document {
            self.event_end = Some(start);
        }
        callbacks.attlist_decl(self, callback, &element, &name, &kind, value, flag);

        true
    }

    /// Adds a content model node under the innermost open group.
    fn add_model_node(&mut self, kind: ContentType) -> usize {
        let index = self.prolog.model.len();
        self.prolog.model.push(ModelNode { kind, quant: ContentQuant::None, name: None, children: Vec::new() });
        if let Some(&group) = self.prolog.groups.last()
            && let Some(parent) = self.prolog.model.get_mut(group)
        {
            parent.children.push(index);
        }

        index
    }

    /// The finished content model as a tree, built children first.
    fn build_model(&self) -> ContentModel {
        let nodes = &self.prolog.model;
        let mut built: Vec<Option<ContentModel>> = vec![None; nodes.len()];
        for index in (0..nodes.len()).rev() {
            let node = &nodes[index];
            let children = node.children.iter().filter_map(|&child| built.get_mut(child).and_then(Option::take)).collect();
            built[index] = Some(ContentModel { kind: node.kind, quant: node.quant, name: node.name.clone(), children });
        }

        built.into_iter().next().flatten().unwrap_or(ContentModel { kind: ContentType::Empty, quant: ContentQuant::None, name: None, children: Vec::new() })
    }

    /// A parameter entity reference in the DTD. `between_decl` is false for a
    /// reference inside a declaration. Returns true when the reference was
    /// consumed, so the default handler does not see it.
    fn reference_param_entity(&mut self, callbacks: &mut dyn Callbacks, name: &[u8], between_decl: bool) -> Result<bool, ErrorCode> {
        self.dtd.borrow_mut().has_param_entity_refs = true;
        if self.param_entity_parsing == ParamEntityParsing::Never {
            let standalone = {
                let mut dtd = self.dtd.borrow_mut();
                dtd.keep_processing = dtd.standalone;
                dtd.standalone
            };
            if !standalone && !self.call_not_standalone(callbacks) {
                return Err(ErrorCode::NotStandalone);
            }
            return Ok(false);
        }

        let (entity, standalone) = {
            let dtd = self.dtd.borrow();
            (dtd.parameter.get(name).cloned(), dtd.standalone)
        };
        // A standalone document entity must declare what it references,
        // outside of parameter entities.
        if standalone && !self.is_param_entity && !self.prolog.in_internal_pe {
            let Some(entity) = &entity else {
                return Err(ErrorCode::UndefinedEntity);
            };
            if !entity.is_internal {
                return Err(ErrorCode::EntityDeclaredInPe);
            }
        }
        let Some(entity) = entity else {
            let mut dtd = self.dtd.borrow_mut();
            dtd.keep_processing = dtd.standalone;
            drop(dtd);
            if between_decl && let Some(callback) = self.handler(HandlerSlot::SkippedEntity) {
                callbacks.skipped_entity(self, callback, name, true);
                return Ok(true);
            }
            return Ok(false);
        };
        if entity.open {
            return Err(ErrorCode::RecursiveEntityRef);
        }

        if let Some(text) = entity.text {
            let name: Rc<[u8]> = Rc::from(name);
            if let Some(entity) = self.dtd.borrow_mut().parameter.get_mut(&name) {
                entity.open = true;
            }
            self.prolog.frames.push(PeFrame { name, text, pos: 0, between_decl });
            return Ok(true);
        }

        let Some(callback) = self.handler(HandlerSlot::ExternalEntityRef) else {
            let mut dtd = self.dtd.borrow_mut();
            dtd.keep_processing = dtd.standalone;
            return Ok(false);
        };
        {
            let mut dtd = self.dtd.borrow_mut();
            dtd.param_entity_read = false;
            if let Some(entity) = dtd.parameter.get_mut(name) {
                entity.open = true;
            }
        }
        let accepted = callbacks.external_entity_ref(
            self,
            callback,
            super::EntityContext::Absent,
            entity.base.as_deref(),
            entity.system_id.as_deref(),
            entity.public_id.as_deref(),
        );
        if let Some(entity) = self.dtd.borrow_mut().parameter.get_mut(name) {
            entity.open = false;
        }
        if !accepted {
            return Err(ErrorCode::ExternalEntityHandling);
        }

        let (read, standalone) = {
            let dtd = self.dtd.borrow();
            (dtd.param_entity_read, dtd.standalone)
        };
        if !read {
            self.dtd.borrow_mut().keep_processing = standalone;
            return Ok(true);
        }
        if !standalone && !self.call_not_standalone(callbacks) {
            return Err(ErrorCode::NotStandalone);
        }

        Ok(true)
    }

    /// Skips an ignored conditional section starting at `pos` in `src`.
    fn skip_ignore_section(&mut self, callbacks: &mut dyn Callbacks, src: &Src, pos: usize) -> Result<PrologStep, ErrorCode> {
        let scan = self.scanner(src).ignore_section(pos);
        let is_document = matches!(src, Src::Document);
        if is_document {
            self.event = Some(pos);
            self.event_end = Some(scan.next);
        }
        match scan.tok {
            Tok::IgnoreSect => {
                if self.has(HandlerSlot::Default) {
                    self.report_default(callbacks, src, pos, scan.next);
                }
                // The parse position moves past the section even if a later
                // token of this call fails.
                if is_document {
                    self.ptr = scan.next;
                }
                if self.phase == Phase::Finished {
                    return Err(ErrorCode::Aborted);
                }
                Ok(PrologStep::IgnoreDone(scan.next))
            }
            Tok::Invalid => {
                if is_document {
                    self.event = Some(scan.next);
                }
                Err(ErrorCode::InvalidToken)
            }
            Tok::PartialChar if !is_document || self.final_buffer => Err(ErrorCode::PartialChar),
            Tok::Partial | Tok::Empty if !is_document || self.final_buffer => Err(ErrorCode::Syntax),
            _ => {
                self.ptr = pos;
                self.stage = Stage::IgnoreSection;
                Ok(PrologStep::Handover)
            }
        }
    }

    pub(super) fn run_ignore_section(&mut self, callbacks: &mut dyn Callbacks, start: usize) -> Result<(), ErrorCode> {
        match self.skip_ignore_section(callbacks, &Src::Document, start)? {
            PrologStep::IgnoreDone(next) => {
                self.stage = Stage::Prolog;
                let scan = self.scanner(&Src::Document).prolog(next);
                self.prolog_loop(callbacks, next, scan)
            }
            _ => Ok(()),
        }
    }

    /// The first parse call of an external parameter entity parser.
    pub(super) fn run_external_param_start(&mut self, callbacks: &mut dyn Callbacks, start: usize) -> Result<(), ErrorCode> {
        self.init_encoding(callbacks)?;
        self.dtd.borrow_mut().param_entity_read = true;
        if self.in_entity_value {
            self.stage = Stage::EntityValueStart;
            return self.run_entity_value_start(callbacks, start);
        }

        self.stage = Stage::ExternalParamToken;
        self.run_external_param_token(callbacks, start)
    }

    /// The first token of an external parameter entity, skipping a byte order mark.
    pub(super) fn run_external_param_token(&mut self, callbacks: &mut dyn Callbacks, start: usize) -> Result<(), ErrorCode> {
        let mut s = start;
        let mut scan = if self.encoding_fixed { self.scanner(&Src::Document).prolog(start) } else { self.first_scan(start, false) };
        let incomplete = scan.open || matches!(scan.tok, Tok::Invalid | Tok::Partial | Tok::PartialChar | Tok::Empty);
        if incomplete {
            if !self.final_buffer && scan.tok != Tok::Invalid {
                self.ptr = start;
                return Ok(());
            }
            match scan.tok {
                Tok::Invalid => return Err(ErrorCode::InvalidToken),
                Tok::Partial => return Err(ErrorCode::UnclosedToken),
                Tok::PartialChar => return Err(ErrorCode::PartialChar),
                _ => {}
            }
        } else if scan.tok == Tok::Bom {
            s = scan.next;
            scan = self.scanner(&Src::Document).prolog(s);
        }

        self.stage = Stage::Prolog;
        self.prolog_loop(callbacks, s, scan)
    }

    /// An external parameter entity read as part of an entity value: an
    /// optional text declaration, then text appended to the value.
    pub(super) fn run_entity_value_start(&mut self, callbacks: &mut dyn Callbacks, start: usize) -> Result<(), ErrorCode> {
        let mut s = start;
        self.event = Some(s);
        let mut first = !self.encoding_fixed;
        loop {
            let scan = if first { self.first_scan(s, false) } else { self.scanner(&Src::Document).prolog(s) };
            first = false;
            self.event_end = Some(scan.next);

            let incomplete = scan.open || matches!(scan.tok, Tok::Invalid | Tok::Partial | Tok::PartialChar | Tok::Empty);
            if incomplete {
                if !self.final_buffer && scan.tok != Tok::Invalid {
                    self.ptr = start;
                    return Ok(());
                }
                return match scan.tok {
                    Tok::Invalid => Err(ErrorCode::InvalidToken),
                    Tok::Partial => Err(ErrorCode::UnclosedToken),
                    Tok::PartialChar => Err(ErrorCode::PartialChar),
                    _ => self.store_entity_value(callbacks, &Src::Document, start, self.data.len()),
                };
            }
            if scan.tok == Tok::XmlDecl {
                self.process_xml_decl(callbacks, false, s, scan.next)?;
                match self.phase {
                    Phase::Suspended => {
                        self.ptr = scan.next;
                        return Ok(());
                    }
                    Phase::Finished => return Err(ErrorCode::Aborted),
                    Phase::Initialized | Phase::Parsing => {}
                }
                self.stage = Stage::EntityValue;
                return self.run_entity_value(callbacks, scan.next);
            }
            if scan.tok == Tok::Bom && scan.next == self.data.len() && !self.final_buffer {
                self.ptr = scan.next;
                return Ok(());
            }

            s = scan.next;
            self.event = Some(s);
        }
    }

    /// The text of an external parameter entity read for an entity value.
    pub(super) fn run_entity_value(&mut self, callbacks: &mut dyn Callbacks, start: usize) -> Result<(), ErrorCode> {
        let mut s = start;
        loop {
            let scan = self.scanner(&Src::Document).prolog(s);
            let incomplete = scan.open || matches!(scan.tok, Tok::Invalid | Tok::Partial | Tok::PartialChar | Tok::Empty);
            if incomplete {
                if !self.final_buffer && scan.tok != Tok::Invalid {
                    self.ptr = s;
                    return Ok(());
                }
                return match scan.tok {
                    Tok::Invalid => Err(ErrorCode::InvalidToken),
                    Tok::Partial => Err(ErrorCode::UnclosedToken),
                    Tok::PartialChar => Err(ErrorCode::PartialChar),
                    _ => self.store_entity_value(callbacks, &Src::Document, start, self.data.len()),
                };
            }
            s = scan.next;
        }
    }

    /// Appends the entity value literal `src[start..end]` to the value being
    /// built: character references and parameter entities are replaced,
    /// line ends normalized.
    fn store_entity_value(&mut self, callbacks: &mut dyn Callbacks, src: &Src, start: usize, end: usize) -> Result<(), ErrorCode> {
        struct ValueFrame {
            src: Src,
            pos: usize,
            end: usize,
            name: Option<Rc<[u8]>>,
        }

        let saved = self.in_entity_value;
        self.in_entity_value = true;
        let mut stack = vec![ValueFrame { src: src.clone(), pos: start, end, name: None }];
        let result = loop {
            let Some(frame) = stack.last() else {
                break Ok(());
            };
            let frame_src = frame.src.clone();
            let pos = frame.pos;
            let frame_end = frame.end;
            let is_document = matches!(frame_src, Src::Document);
            let scan = self.scanner(&frame_src).entity_value(pos, frame_end);
            let next = scan.next;
            if let Some(frame) = stack.last_mut() {
                frame.pos = next;
            }

            match scan.tok {
                Tok::Empty => {
                    if let Some(name) = stack.pop().and_then(|frame| frame.name)
                        && let Some(entity) = self.dtd.borrow_mut().parameter.get_mut(&name)
                    {
                        entity.open = false;
                    }
                }
                Tok::Data | Tok::EntityRef => {
                    let text = self.utf8(&frame_src, pos, next);
                    self.dtd.borrow_mut().entity_value.extend_from_slice(&text);
                }
                Tok::TrailingCr | Tok::Newline => self.dtd.borrow_mut().entity_value.push(b'\n'),
                Tok::CharRef => {
                    let (buf, enc) = self.src_parts(&frame_src);
                    let Some(code) = char_ref_value(buf, pos, next, enc) else {
                        if is_document {
                            self.event = Some(pos);
                        }
                        break Err(ErrorCode::BadCharRef);
                    };
                    push_utf8(code, &mut self.dtd.borrow_mut().entity_value);
                }
                Tok::ParamEntityRef => {
                    if !self.is_param_entity && is_document {
                        self.event = Some(pos);
                        break Err(ErrorCode::ParamEntityRef);
                    }
                    let unit = self.unit(&frame_src);
                    let name: Rc<[u8]> = Rc::from(self.utf8(&frame_src, pos + unit, next - unit));
                    let entity = self.dtd.borrow().parameter.get(&name).cloned();
                    let Some(entity) = entity else {
                        let mut dtd = self.dtd.borrow_mut();
                        dtd.keep_processing = dtd.standalone;
                        break Ok(());
                    };
                    if entity.open {
                        if is_document {
                            self.event = Some(pos);
                        }
                        break Err(ErrorCode::RecursiveEntityRef);
                    }
                    if let Some(text) = entity.text {
                        if let Some(entity) = self.dtd.borrow_mut().parameter.get_mut(&name) {
                            entity.open = true;
                        }
                        let end = text.len();
                        stack.push(ValueFrame { src: Src::Text(text), pos: 0, end, name: Some(name) });
                        continue;
                    }
                    let Some(callback) = self.handler(HandlerSlot::ExternalEntityRef) else {
                        let mut dtd = self.dtd.borrow_mut();
                        dtd.keep_processing = dtd.standalone;
                        continue;
                    };
                    {
                        let mut dtd = self.dtd.borrow_mut();
                        dtd.param_entity_read = false;
                        if let Some(entity) = dtd.parameter.get_mut(&name) {
                            entity.open = true;
                        }
                    }
                    let accepted = callbacks.external_entity_ref(
                        self,
                        callback,
                        super::EntityContext::Absent,
                        entity.base.as_deref(),
                        entity.system_id.as_deref(),
                        entity.public_id.as_deref(),
                    );
                    if let Some(entity) = self.dtd.borrow_mut().parameter.get_mut(&name) {
                        entity.open = false;
                    }
                    if !accepted {
                        break Err(ErrorCode::ExternalEntityHandling);
                    }
                    let mut dtd = self.dtd.borrow_mut();
                    if !dtd.param_entity_read {
                        dtd.keep_processing = dtd.standalone;
                    }
                }
                Tok::Partial => {
                    if is_document {
                        self.event = Some(pos);
                    }
                    break Err(ErrorCode::InvalidToken);
                }
                Tok::Invalid => {
                    if is_document {
                        self.event = Some(next);
                    }
                    break Err(ErrorCode::InvalidToken);
                }
                _ => {
                    if is_document {
                        self.event = Some(pos);
                    }
                    break Err(ErrorCode::UnexpectedState);
                }
            }
        };

        for frame in stack {
            if let Some(name) = frame.name
                && let Some(entity) = self.dtd.borrow_mut().parameter.get_mut(&name)
            {
                entity.open = false;
            }
        }
        self.in_entity_value = saved;

        result
    }

    /// Processes an XML declaration (or a text declaration in an external
    /// entity) spanning `start..end` of the input.
    pub(super) fn process_xml_decl(&mut self, callbacks: &mut dyn Callbacks, is_text_decl: bool, start: usize, end: usize) -> Result<(), ErrorCode> {
        let parts = match self.parse_xml_decl(is_text_decl, start, end) {
            Ok(parts) => parts,
            Err(bad) => {
                self.event = Some(bad);
                return Err(if is_text_decl { ErrorCode::TextDecl } else { ErrorCode::XmlDecl });
            }
        };

        if !is_text_decl && parts.standalone == 1 {
            self.dtd.borrow_mut().standalone = true;
            if self.param_entity_parsing == ParamEntityParsing::UnlessStandalone {
                self.param_entity_parsing = ParamEntityParsing::Never;
            }
        }

        let encoding_name = parts.encoding.map(|(from, to)| self.utf8(&Src::Document, from, to));
        if let Some(callback) = self.handler(HandlerSlot::XmlDecl) {
            let version = parts.version.map(|(from, to)| self.utf8(&Src::Document, from, to));
            callbacks.xml_decl(self, callback, version.as_deref(), encoding_name.as_deref(), parts.standalone);
        } else if self.has(HandlerSlot::Default) {
            self.report_default(callbacks, &Src::Document, start, end);
        }

        if self.protocol_encoding.is_some() {
            return Ok(());
        }
        let (Some(name), Some((name_start, _))) = (encoding_name, parts.encoding) else {
            return Ok(());
        };

        match known_declared_encoding(&name, &self.encoding) {
            Some(encoding) => {
                if encoding.unit() != self.encoding.unit() {
                    self.event = Some(name_start);
                    return Err(ErrorCode::IncorrectEncoding);
                }
                self.encoding = encoding;
                Ok(())
            }
            None => match self.unknown_encoding(callbacks, &name) {
                Some(encoding) => {
                    self.encoding = encoding;
                    Ok(())
                }
                None => {
                    self.event = Some(name_start);
                    Err(ErrorCode::UnknownEncoding)
                }
            },
        }
    }

    /// Splits the pseudo-attributes of an XML or text declaration. The error
    /// is the position of the first problem.
    fn parse_xml_decl(&self, is_text_decl: bool, start: usize, end: usize) -> Result<XmlDeclParts, usize> {
        let unit = self.encoding.unit();
        let decl = DeclReader { buf: &self.data, enc: &self.encoding, end: end - 2 * unit };
        let mut parts = XmlDeclParts { version: None, encoding: None, standalone: -1 };
        let mut pos = start + 5 * unit;

        let mut attribute = decl.attribute(pos)?;
        let Some(mut current) = attribute else {
            return Err(pos);
        };
        if decl.matches(current.name, b"version") {
            parts.version = Some(current.value);
            pos = current.next;
            attribute = decl.attribute(pos)?;
            let Some(found) = attribute else {
                return if is_text_decl { Err(pos) } else { Ok(parts) };
            };
            current = found;
        } else if !is_text_decl {
            return Err(current.name.0);
        }

        if decl.matches(current.name, b"encoding") {
            let first = decl.ascii(current.value.0);
            if !first.is_some_and(|byte| byte.is_ascii_alphabetic()) {
                return Err(current.value.0);
            }
            parts.encoding = Some(current.value);
            pos = current.next;
            let Some(found) = decl.attribute(pos)? else {
                return Ok(parts);
            };
            current = found;
        }

        if !decl.matches(current.name, b"standalone") || is_text_decl {
            return Err(current.name.0);
        }
        if decl.matches(current.value, b"yes") {
            parts.standalone = 1;
        } else if decl.matches(current.value, b"no") {
            parts.standalone = 0;
        } else {
            return Err(current.value.0);
        }

        let mut pos = current.next;
        while decl.ascii(pos).is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n')) {
            pos += unit;
        }
        if pos != decl.end {
            return Err(pos);
        }

        Ok(parts)
    }
}

/// The outcome of one prolog token.
pub(super) enum PrologStep {
    Continue,
    /// An ignored section was skipped; the next token starts at the position.
    IgnoreDone(usize),
    /// Another processor took over the input, or an ignored section continues
    /// past it; the prolog loop returns.
    Handover,
}

/// A pseudo-attribute of an XML declaration: name and value spans, and the
/// position after the closing quote.
#[derive(Clone, Copy)]
struct PseudoAttribute {
    name: (usize, usize),
    value: (usize, usize),
    next: usize,
}

/// Reads the pseudo-attributes of an XML declaration up to `end`.
struct DeclReader<'a> {
    buf: &'a [u8],
    enc: &'a Encoding,
    end: usize,
}

impl DeclReader<'_> {
    /// The character at `pos` as the declaration reader sees it: the ASCII
    /// value, -1 at the end or where no single byte represents it, and for
    /// the byte-oriented encodings the signed value of a byte that may start
    /// a multibyte character.
    fn code(&self, pos: usize) -> i32 {
        if pos >= self.end {
            return -1;
        }

        let byte = self.buf.get(pos).copied().unwrap_or(0);
        match self.enc {
            Encoding::Utf8 if byte & 0xC0 == 0x80 => -1,
            Encoding::Utf8 | Encoding::Ascii => i32::from(byte as i8),
            Encoding::Mapped(_) => match self.enc.raw_unit(self.buf, pos) {
                u32::MAX => 0,
                code if code < 0x80 => code as i32,
                _ => -1,
            },
            _ => match self.enc.raw_unit(self.buf, pos) {
                code if code < 0x80 => code as i32,
                _ => -1,
            },
        }
    }

    /// The ASCII character at `pos`, if the reader sees one there.
    fn ascii(&self, pos: usize) -> Option<u8> {
        u8::try_from(self.code(pos)).ok().filter(u8::is_ascii)
    }

    fn is_space(&self, pos: usize) -> bool {
        self.ascii(pos).is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    }

    fn matches(&self, span: (usize, usize), word: &[u8]) -> bool {
        let unit = self.enc.unit();
        if span.1 - span.0 != word.len() * unit {
            return false;
        }

        word.iter().enumerate().all(|(index, &byte)| self.code(span.0 + index * unit) == i32::from(byte))
    }

    /// The next pseudo-attribute at `pos`, `None` when only white space
    /// remains, or the position of the error.
    fn attribute(&self, mut pos: usize) -> Result<Option<PseudoAttribute>, usize> {
        let unit = self.enc.unit();
        if pos == self.end {
            return Ok(None);
        }
        if !self.is_space(pos) {
            return Err(pos);
        }
        while self.is_space(pos) {
            pos += unit;
        }
        if pos == self.end {
            return Ok(None);
        }

        let name_start = pos;
        let name_end;
        loop {
            let code = self.code(pos);
            if code == -1 {
                return Err(pos);
            }
            if code == i32::from(b'=') {
                name_end = pos;
                break;
            }
            if self.is_space(pos) {
                name_end = pos;
                while self.is_space(pos) {
                    pos += unit;
                }
                if self.code(pos) != i32::from(b'=') {
                    return Err(pos);
                }
                break;
            }
            pos += unit;
        }
        if name_end == name_start {
            return Err(pos);
        }

        pos += unit;
        while self.is_space(pos) {
            pos += unit;
        }
        let quote = match self.ascii(pos) {
            Some(quote @ (b'"' | b'\'')) => quote,
            _ => return Err(pos),
        };
        pos += unit;
        let value_start = pos;
        loop {
            let byte = self.ascii(pos);
            if byte == Some(quote) {
                break;
            }
            if !byte.is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')) {
                return Err(pos);
            }
            pos += unit;
        }

        Ok(Some(PseudoAttribute { name: (name_start, name_end), value: (value_start, pos), next: pos + unit }))
    }
}

/// The decoder for an encoding named in an XML declaration, if the parser
/// knows it. "UTF-16" keeps a UTF-16 stream's byte order.
fn known_declared_encoding(name: &[u8], current: &Encoding) -> Option<Encoding> {
    const LONGEST_NAME: usize = 128;

    if name.len() >= LONGEST_NAME {
        return None;
    }
    let known = KnownEncoding::from_name(name)?;
    if known == KnownEncoding::Utf16 && current.unit() == 2 {
        return Some(current.clone());
    }

    Some(known.encoding())
}

fn content_quant(quant: Quant) -> ContentQuant {
    match quant {
        Quant::One => ContentQuant::None,
        Quant::Opt => ContentQuant::Opt,
        Quant::Rep => ContentQuant::Rep,
        Quant::Plus => ContentQuant::Plus,
    }
}

/// Whether an attribute name declares a namespace.
pub(super) fn is_xmlns_attribute(name: &[u8]) -> bool {
    name.starts_with(b"xmlns") && (name.len() == 5 || name.get(5) == Some(&b':'))
}
