//! The content processor: elements, attributes, namespaces, character data,
//! CDATA sections, entity references and the epilog after the document element.

use std::collections::HashSet;
use std::mem;
use std::ops::Range;
use std::rc::Rc;

use super::Attributes;
use super::Callbacks;
use super::ErrorCode;
use super::HandlerSlot;
use super::encoding::push_utf8;
use super::parser::Binding;
use super::parser::OpenTag;
use super::parser::Parser;
use super::parser::Phase;
use super::parser::Stage;
use super::parser::XML_NAMESPACE;
use super::parser::XMLNS_NAMESPACE;
use super::prolog::Src;
use super::prolog::is_xmlns_attribute;
use super::scan::RawAttribute;
use super::scan::Scan;
use super::scan::Tok;
use super::values::char_ref_value;
use super::values::predefined_entity;

/// An internal general entity whose replacement text is being processed.
#[derive(Clone, Debug)]
struct EntityFrame {
    name: Rc<[u8]>,
    text: Rc<[u8]>,
    pos: usize,
    /// The element depth when the reference occurred; the text must leave it unchanged.
    depth: usize,
}

/// What the content processor keeps between tokens.
#[derive(Clone, Debug, Default)]
pub(super) struct ContentState {
    pub tags: Vec<OpenTag>,
    frames: Vec<EntityFrame>,
    raw_attributes: Vec<RawAttribute>,
}

/// How the end of the data is treated where content may end.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Level {
    /// The content of the document element.
    Document,
    /// An entity, which must close the elements it opens; `depth` is the
    /// element depth at its start.
    Entity { depth: usize },
}

/// The outcome of one content token.
enum Flow {
    /// Continue with the token at the position.
    Next(usize),
    /// The token is incomplete; wait for more input.
    Wait,
    /// The data of an entity ended.
    End,
    /// The document element ended; the epilog starts at the position.
    Epilog(usize),
    /// A CDATA section continues beyond the available input from the position.
    CdataPending(usize),
}

/// One attribute as reported, plus whether its name still needs a namespace.
struct AttributeOut {
    name: Vec<u8>,
    value: Vec<u8>,
    prefixed: bool,
}

impl Parser {
    pub(super) fn run_content(&mut self, callbacks: &mut dyn Callbacks, start: usize) -> Result<(), ErrorCode> {
        let level = if self.stage == Stage::ExternalEntityContent { Level::Entity { depth: 0 } } else { Level::Document };
        if level == Level::Document {
            self.stage = Stage::Content;
        }

        self.content_loop(callbacks, start, level)
    }

    fn content_loop(&mut self, callbacks: &mut dyn Callbacks, mut s: usize, level: Level) -> Result<(), ErrorCode> {
        let have_more = !self.final_buffer;
        self.event = Some(s);
        loop {
            let scan = self.scanner(&Src::Document).content(s);
            self.event_end = Some(scan.next);

            let flow = self.content_token(callbacks, &Src::Document, scan, s, have_more, level)?;
            let next = match flow {
                Flow::Next(next) => next,
                Flow::Wait => {
                    self.ptr = s;
                    return Ok(());
                }
                Flow::End => {
                    self.ptr = scan.next.max(s);
                    return Ok(());
                }
                Flow::Epilog(next) => return self.run_epilog(callbacks, next),
                Flow::CdataPending(at) => {
                    self.ptr = at;
                    self.stage = Stage::CdataSection;
                    return Ok(());
                }
            };
            self.run_entity_frames(callbacks)?;

            self.event = Some(next);
            s = next;
            match self.phase {
                Phase::Suspended => {
                    self.ptr = next;
                    return Ok(());
                }
                Phase::Finished => return Err(ErrorCode::Aborted),
                Phase::Initialized | Phase::Parsing => {}
            }
        }
    }

    /// Processes the replacement text of the internal entities pushed by a reference.
    fn run_entity_frames(&mut self, callbacks: &mut dyn Callbacks) -> Result<(), ErrorCode> {
        while let Some(frame) = self.content.frames.last() {
            let index = self.content.frames.len() - 1;
            let src = Src::Text(Rc::clone(&frame.text));
            let pos = frame.pos;
            let level = Level::Entity { depth: frame.depth };
            let scan = self.scanner(&src).content(pos);

            match self.content_token(callbacks, &src, scan, pos, false, level)? {
                // A reference in the text may have pushed frames above this one.
                Flow::Next(next) => {
                    if let Some(frame) = self.content.frames.get_mut(index) {
                        frame.pos = next;
                    }
                }
                Flow::End => {
                    if let Some(frame) = self.content.frames.pop()
                        && let Some(entity) = self.dtd.borrow_mut().general.get_mut(&frame.name)
                    {
                        entity.open = false;
                    }
                    continue;
                }
                Flow::Wait | Flow::Epilog(_) | Flow::CdataPending(_) => return Err(ErrorCode::UnexpectedState),
            }

            match self.phase {
                Phase::Suspended => return Ok(()),
                Phase::Finished => return Err(ErrorCode::Aborted),
                Phase::Initialized | Phase::Parsing => {}
            }
        }

        Ok(())
    }

    /// Handles one content token from `src` that starts at `s`.
    fn content_token(&mut self, callbacks: &mut dyn Callbacks, src: &Src, scan: Scan, s: usize, have_more: bool, level: Level) -> Result<Flow, ErrorCode> {
        let is_document = matches!(src, Src::Document);
        let next = scan.next;
        let unit = self.src_parts(src).1.unit();

        match scan.tok {
            Tok::Invalid => {
                if is_document {
                    self.event = Some(next);
                }
                Err(ErrorCode::InvalidToken)
            }
            Tok::PartialChar => {
                if have_more {
                    return Ok(Flow::Wait);
                }
                Err(ErrorCode::PartialChar)
            }
            Tok::Partial => {
                if have_more {
                    return Ok(Flow::Wait);
                }
                Err(ErrorCode::UnclosedToken)
            }
            Tok::Empty => {
                if have_more {
                    return Ok(Flow::Wait);
                }
                match level {
                    Level::Document => Err(ErrorCode::NoElements),
                    Level::Entity { depth } if depth != self.content.tags.len() => Err(ErrorCode::AsyncEntity),
                    Level::Entity { .. } => Ok(Flow::End),
                }
            }
            Tok::TrailingCr | Tok::TrailingRsqb => {
                if have_more {
                    return Ok(Flow::Wait);
                }
                let end = self.src_parts(src).0.len();
                if scan.tok == Tok::TrailingCr {
                    if let Some(callback) = self.handler(HandlerSlot::CharacterData) {
                        callbacks.character_data(self, callback, b"\n");
                    } else if self.has(HandlerSlot::Default) {
                        self.report_default(callbacks, src, s, end);
                    }
                } else {
                    self.report_data(callbacks, src, s, end);
                }
                match level {
                    Level::Document => {
                        if is_document && scan.tok == Tok::TrailingRsqb {
                            self.event = Some(end);
                        }
                        Err(ErrorCode::NoElements)
                    }
                    Level::Entity { depth } if depth != self.content.tags.len() => {
                        if is_document && scan.tok == Tok::TrailingRsqb {
                            self.event = Some(end);
                        }
                        Err(ErrorCode::AsyncEntity)
                    }
                    Level::Entity { .. } => Ok(Flow::End),
                }
            }
            Tok::Newline => {
                if let Some(callback) = self.handler(HandlerSlot::CharacterData) {
                    callbacks.character_data(self, callback, b"\n");
                } else if self.has(HandlerSlot::Default) {
                    self.report_default(callbacks, src, s, next);
                }
                Ok(Flow::Next(next))
            }
            Tok::Data => {
                self.report_data(callbacks, src, s, next);
                Ok(Flow::Next(next))
            }
            Tok::CharRef => {
                let (buf, enc) = self.src_parts(src);
                let Some(code) = char_ref_value(buf, s, next, enc) else {
                    return Err(ErrorCode::BadCharRef);
                };
                if let Some(callback) = self.handler(HandlerSlot::CharacterData) {
                    let mut text = Vec::with_capacity(4);
                    push_utf8(code, &mut text);
                    callbacks.character_data(self, callback, &text);
                } else if self.has(HandlerSlot::Default) {
                    self.report_default(callbacks, src, s, next);
                }
                Ok(Flow::Next(next))
            }
            Tok::EntityRef => {
                let name = self.utf8(src, s + unit, next - unit);
                self.reference_entity(callbacks, src, s, next, &name)?;
                Ok(Flow::Next(next))
            }
            Tok::StartTag | Tok::EmptyElement => self.start_tag(callbacks, src, s, next, scan.tok == Tok::EmptyElement, level),
            Tok::EndTag => self.end_tag(callbacks, src, s, next, level),
            Tok::CdataOpen => {
                if let Some(callback) = self.handler(HandlerSlot::StartCdataSection) {
                    callbacks.start_cdata_section(self, callback);
                } else if self.has(HandlerSlot::Default) {
                    self.report_default(callbacks, src, s, next);
                }
                match self.cdata_section(callbacks, src, next, have_more)? {
                    Some(after) => Ok(Flow::Next(after)),
                    None if is_document => Ok(Flow::CdataPending(self.ptr)),
                    // Only a stopped parser leaves a section in replacement text unfinished.
                    None => Ok(Flow::Next(next)),
                }
            }
            Tok::Pi => {
                self.report_pi(callbacks, src, s, next);
                Ok(Flow::Next(next))
            }
            Tok::Comment => {
                self.report_comment(callbacks, src, s, next);
                Ok(Flow::Next(next))
            }
            Tok::XmlDecl => Err(ErrorCode::MisplacedXmlPi),
            _ => {
                if self.has(HandlerSlot::Default) {
                    self.report_default(callbacks, src, s, next);
                }
                Ok(Flow::Next(next))
            }
        }
    }

    /// Reports character data `src[start..end]` to the character data handler
    /// in pieces of converted text, or else to the default handler.
    fn report_data(&mut self, callbacks: &mut dyn Callbacks, src: &Src, start: usize, end: usize) {
        // The handler installed when the token starts receives all its pieces.
        let Some(callback) = self.handler(HandlerSlot::CharacterData) else {
            if self.has(HandlerSlot::Default) {
                self.report_default(callbacks, src, start, end);
            }
            return;
        };

        let is_document = matches!(src, Src::Document);
        let mut pos = start;
        loop {
            let (buf, enc) = self.src_parts(src);
            let piece_end = enc.piece_end(buf, pos, end);
            let mut text = Vec::with_capacity(piece_end - pos);
            enc.append_utf8(buf, pos, piece_end, &mut text);
            if is_document && !enc.is_utf8() {
                self.event_end = Some(piece_end);
            }
            callbacks.character_data(self, callback, &text);
            if piece_end >= end {
                return;
            }
            pos = piece_end;
            if is_document {
                self.event = Some(pos);
            }
        }
    }

    /// A CDATA section's content from `start`. `Some` is the position after
    /// `]]>`; `None` means the section continues past the available input,
    /// with `ptr` set to where scanning resumes.
    fn cdata_section(&mut self, callbacks: &mut dyn Callbacks, src: &Src, start: usize, have_more: bool) -> Result<Option<usize>, ErrorCode> {
        let is_document = matches!(src, Src::Document);
        let mut s = start;
        if is_document {
            self.event = Some(s);
        }
        loop {
            let scan = self.scanner(src).cdata(s);
            let next = scan.next;
            if is_document {
                self.event_end = Some(next);
            }

            match scan.tok {
                Tok::CdataClose => {
                    if let Some(callback) = self.handler(HandlerSlot::EndCdataSection) {
                        callbacks.end_cdata_section(self, callback);
                    } else if self.has(HandlerSlot::Default) {
                        self.report_default(callbacks, src, s, next);
                    }
                    // The parse position moves past the section even if a later
                    // token of this call fails.
                    if is_document {
                        self.ptr = next;
                    }
                    if self.phase == Phase::Finished {
                        return Err(ErrorCode::Aborted);
                    }
                    return Ok(Some(next));
                }
                Tok::Newline => {
                    if let Some(callback) = self.handler(HandlerSlot::CharacterData) {
                        callbacks.character_data(self, callback, b"\n");
                    } else if self.has(HandlerSlot::Default) {
                        self.report_default(callbacks, src, s, next);
                    }
                }
                Tok::Data => self.report_data(callbacks, src, s, next),
                Tok::Invalid => {
                    if is_document {
                        self.event = Some(next);
                    }
                    return Err(ErrorCode::InvalidToken);
                }
                Tok::PartialChar => {
                    if have_more {
                        self.ptr = s;
                        return Ok(None);
                    }
                    return Err(ErrorCode::PartialChar);
                }
                Tok::Partial | Tok::Empty => {
                    if have_more {
                        self.ptr = s;
                        return Ok(None);
                    }
                    return Err(ErrorCode::UnclosedCdataSection);
                }
                _ => {
                    if is_document {
                        self.event = Some(next);
                    }
                    return Err(ErrorCode::UnexpectedState);
                }
            }

            s = next;
            if is_document {
                self.event = Some(s);
            }
            match self.phase {
                Phase::Suspended => {
                    self.ptr = next;
                    return Ok(None);
                }
                Phase::Finished => return Err(ErrorCode::Aborted),
                Phase::Initialized | Phase::Parsing => {}
            }
        }
    }

    pub(super) fn run_cdata_section(&mut self, callbacks: &mut dyn Callbacks, start: usize) -> Result<(), ErrorCode> {
        let have_more = !self.final_buffer;
        let Some(after) = self.cdata_section(callbacks, &Src::Document, start, have_more)? else {
            return Ok(());
        };

        if self.is_child {
            self.stage = Stage::ExternalEntityContent;
            return self.content_loop(callbacks, after, Level::Entity { depth: 0 });
        }
        self.stage = Stage::Content;

        self.content_loop(callbacks, after, Level::Document)
    }

    pub(super) fn run_epilog(&mut self, callbacks: &mut dyn Callbacks, start: usize) -> Result<(), ErrorCode> {
        self.stage = Stage::Epilog;
        let mut s = start;
        self.event = Some(s);
        loop {
            let scan = self.scanner(&Src::Document).prolog(s);
            let next = scan.next;
            self.event_end = Some(next);

            match scan.tok {
                Tok::Space if scan.open => {
                    if self.has(HandlerSlot::Default) {
                        self.report_default(callbacks, &Src::Document, s, next);
                        if self.phase == Phase::Finished {
                            return Err(ErrorCode::Aborted);
                        }
                    }
                    self.ptr = next;
                    return Ok(());
                }
                Tok::Empty => {
                    self.ptr = s;
                    return Ok(());
                }
                Tok::Space => {
                    if self.has(HandlerSlot::Default) {
                        self.report_default(callbacks, &Src::Document, s, next);
                    }
                }
                Tok::Pi => self.report_pi(callbacks, &Src::Document, s, next),
                Tok::Comment => self.report_comment(callbacks, &Src::Document, s, next),
                Tok::Invalid => {
                    self.event = Some(next);
                    return Err(ErrorCode::InvalidToken);
                }
                Tok::Partial | Tok::PartialChar => {
                    if !self.final_buffer {
                        self.ptr = s;
                        return Ok(());
                    }
                    return Err(if scan.tok == Tok::Partial { ErrorCode::UnclosedToken } else { ErrorCode::PartialChar });
                }
                _ => return Err(ErrorCode::JunkAfterDocElement),
            }

            s = next;
            self.event = Some(s);
            match self.phase {
                Phase::Suspended => {
                    self.ptr = next;
                    return Ok(());
                }
                Phase::Finished => return Err(ErrorCode::Aborted),
                Phase::Initialized | Phase::Parsing => {}
            }
        }
    }

    /// The first parse call of an external parsed entity parser: the encoding.
    pub(super) fn run_external_entity_start(&mut self, callbacks: &mut dyn Callbacks, start: usize) -> Result<(), ErrorCode> {
        self.init_protocol_encoding(callbacks)?;
        self.stage = Stage::ExternalEntityBom;

        self.run_external_entity_bom(callbacks, start)
    }

    /// Skips a byte order mark at the start of an external parsed entity.
    pub(super) fn run_external_entity_bom(&mut self, callbacks: &mut dyn Callbacks, start: usize) -> Result<(), ErrorCode> {
        let mut start = start;
        let scan = if self.encoding_fixed { self.scanner(&Src::Document).content(start) } else { self.first_scan(start, true) };
        match scan.tok {
            Tok::Bom => {
                if scan.next == self.data.len() && !self.final_buffer {
                    self.ptr = scan.next;
                    return Ok(());
                }
                start = scan.next;
            }
            Tok::Partial | Tok::PartialChar => {
                if !self.final_buffer {
                    self.ptr = start;
                    return Ok(());
                }
                self.event = Some(start);
                return Err(if scan.tok == Tok::Partial { ErrorCode::UnclosedToken } else { ErrorCode::PartialChar });
            }
            _ => {}
        }
        self.stage = Stage::ExternalEntityDecl;

        self.run_external_entity_decl(callbacks, start)
    }

    /// Reads the optional text declaration of an external parsed entity.
    pub(super) fn run_external_entity_decl(&mut self, callbacks: &mut dyn Callbacks, start: usize) -> Result<(), ErrorCode> {
        let mut start = start;
        self.event = Some(start);
        let scan = self.scanner(&Src::Document).content(start);
        self.event_end = Some(scan.next);
        match scan.tok {
            Tok::XmlDecl => {
                self.process_xml_decl(callbacks, true, start, scan.next)?;
                match self.phase {
                    Phase::Suspended => {
                        self.ptr = scan.next;
                        return Ok(());
                    }
                    Phase::Finished => return Err(ErrorCode::Aborted),
                    Phase::Initialized | Phase::Parsing => start = scan.next,
                }
            }
            Tok::Partial | Tok::PartialChar => {
                if !self.final_buffer {
                    self.ptr = start;
                    return Ok(());
                }
                return Err(if scan.tok == Tok::Partial { ErrorCode::UnclosedToken } else { ErrorCode::PartialChar });
            }
            _ => {}
        }
        self.stage = Stage::ExternalEntityContent;

        self.content_loop(callbacks, start, Level::Entity { depth: 0 })
    }

    /// A general entity reference `src[s..next]` to `name` in content.
    fn reference_entity(&mut self, callbacks: &mut dyn Callbacks, src: &Src, s: usize, next: usize, name: &[u8]) -> Result<(), ErrorCode> {
        if let Some(byte) = predefined_entity(name) {
            if let Some(callback) = self.handler(HandlerSlot::CharacterData) {
                callbacks.character_data(self, callback, &[byte]);
            } else if self.has(HandlerSlot::Default) {
                self.report_default(callbacks, src, s, next);
            }
            return Ok(());
        }

        let (entity, must_exist) = {
            let dtd = self.dtd.borrow();
            (dtd.general.get(name).cloned(), !dtd.has_param_entity_refs || dtd.standalone)
        };
        let Some(entity) = entity else {
            if must_exist {
                return Err(ErrorCode::UndefinedEntity);
            }
            if let Some(callback) = self.handler(HandlerSlot::SkippedEntity) {
                callbacks.skipped_entity(self, callback, name, false);
            } else if self.has(HandlerSlot::Default) {
                self.report_default(callbacks, src, s, next);
            }
            return Ok(());
        };
        if must_exist && !entity.is_internal {
            return Err(ErrorCode::EntityDeclaredInPe);
        }
        if entity.open || self.inherited_open.iter().any(|open| &**open == name) {
            return Err(ErrorCode::RecursiveEntityRef);
        }
        if entity.notation.is_some() {
            return Err(ErrorCode::BinaryEntityRef);
        }

        if let Some(text) = entity.text {
            if !self.default_expand {
                if let Some(callback) = self.handler(HandlerSlot::SkippedEntity) {
                    callbacks.skipped_entity(self, callback, name, false);
                } else if self.has(HandlerSlot::Default) {
                    self.report_default(callbacks, src, s, next);
                }
                return Ok(());
            }
            let name: Rc<[u8]> = Rc::from(name);
            if let Some(entity) = self.dtd.borrow_mut().general.get_mut(&name) {
                entity.open = true;
            }
            let depth = self.content.tags.len();
            self.content.frames.push(EntityFrame { name, text, pos: 0, depth });
            return Ok(());
        }

        let Some(callback) = self.handler(HandlerSlot::ExternalEntityRef) else {
            if self.has(HandlerSlot::Default) {
                self.report_default(callbacks, src, s, next);
            }
            return Ok(());
        };
        let context = {
            if let Some(entity) = self.dtd.borrow_mut().general.get_mut(name) {
                entity.open = true;
            }
            let context = self.context();
            if let Some(entity) = self.dtd.borrow_mut().general.get_mut(name) {
                entity.open = false;
            }
            context
        };
        let accepted = callbacks.external_entity_ref(
            self,
            callback,
            Parser::entity_context(&context),
            entity.base.as_deref(),
            entity.system_id.as_deref(),
            entity.public_id.as_deref(),
        );
        drop(context);
        if !accepted {
            return Err(ErrorCode::ExternalEntityHandling);
        }

        Ok(())
    }

    /// A start tag or empty element tag `src[s..next]`.
    fn start_tag(&mut self, callbacks: &mut dyn Callbacks, src: &Src, s: usize, next: usize, empty: bool, level: Level) -> Result<Flow, ErrorCode> {
        let is_document = matches!(src, Src::Document);
        let unit = self.src_parts(src).1.unit();
        let raw_name_end = self.scanner(src).name_end(s + unit);
        let raw_name = self.src_parts(src).0.get(s + unit..raw_name_end).unwrap_or_default().to_vec();
        let qname = self.utf8(src, s + unit, raw_name_end);

        let mut raw_attributes = mem::take(&mut self.content.raw_attributes);
        self.scanner(src).attributes(s, &mut raw_attributes);
        let binding_mark = self.bindings.len();
        let result = self.collect_attributes(callbacks, src, &qname, &raw_attributes);
        self.content.raw_attributes = raw_attributes;
        let (attributes, specified) = result?;
        let new_bindings = self.bindings.len() - binding_mark;

        let name: Rc<[u8]> = Rc::from(self.expand_element_name(&qname)?);

        let mut bytes = Vec::new();
        let mut spans: Vec<Range<usize>> = Vec::with_capacity(attributes.len() * 2);
        for attribute in &attributes {
            for part in [&attribute.name, &attribute.value] {
                let start = bytes.len();
                bytes.extend_from_slice(part);
                spans.push(start..bytes.len());
            }
        }
        self.specified_count = (specified * 2) as i32;

        let start_handler = self.handler(HandlerSlot::StartElement);
        if let Some(callback) = start_handler {
            callbacks.start_element(self, callback, &name, Attributes::new(&bytes, &spans));
        }

        if !empty {
            if start_handler.is_none() && self.has(HandlerSlot::Default) {
                self.report_default(callbacks, src, s, next);
            }
            self.content.tags.push(OpenTag { raw_name, name, bindings: new_bindings });
            return Ok(Flow::Next(next));
        }

        let mut reported = start_handler.is_some();
        if let Some(callback) = self.handler(HandlerSlot::EndElement) {
            if self.has(HandlerSlot::StartElement) && is_document {
                self.event = self.event_end;
            }
            callbacks.end_element(self, callback, &name);
            reported = true;
        }
        if !reported && self.has(HandlerSlot::Default) {
            self.report_default(callbacks, src, s, next);
        }
        self.end_bindings(callbacks, new_bindings);

        if level == Level::Document && self.content.tags.is_empty() && is_document {
            return Ok(Flow::Epilog(next));
        }

        Ok(Flow::Next(next))
    }

    /// The attributes of a start tag with their values normalized, namespace
    /// declarations applied and defaults added, and the number of specified ones.
    fn collect_attributes(
        &mut self,
        callbacks: &mut dyn Callbacks,
        src: &Src,
        element: &[u8],
        raw: &[RawAttribute],
    ) -> Result<(Vec<AttributeOut>, usize), ErrorCode> {
        let is_document = matches!(src, Src::Document);
        let ns = self.ns_separator.is_some();
        // An element type without declarations has no defaults and only CDATA attributes.
        let element_type = self.dtd.borrow().element(element).unwrap_or_default();

        let mut out: Vec<AttributeOut> = Vec::with_capacity(raw.len());
        let mut seen: HashSet<Vec<u8>> = HashSet::with_capacity(raw.len());
        for attribute in raw {
            let name = self.utf8(src, attribute.name.0, attribute.name.1);
            if !seen.insert(name.clone()) {
                if is_document {
                    self.event = Some(attribute.name.0);
                }
                return Err(ErrorCode::DuplicateAttribute);
            }

            let is_cdata = element_type.is_cdata(&name);
            let mut value = Vec::new();
            self.normalize_attribute_value(src, is_cdata, attribute.value.0, attribute.value.1, false, &mut value)?;

            if ns && is_xmlns_attribute(&name) {
                self.declare_namespace(callbacks, &name, value)?;
                continue;
            }
            let prefixed = ns && name.contains(&b':');
            out.push(AttributeOut { name, value, prefixed });
        }
        let specified = out.len();

        for declared in &element_type.attributes {
            let Some(value) = &declared.value else {
                continue;
            };
            if !seen.insert(declared.name.to_vec()) {
                continue;
            }
            if ns && is_xmlns_attribute(&declared.name) {
                self.declare_namespace(callbacks, &declared.name, value.to_vec())?;
                continue;
            }
            let prefixed = ns && declared.name.contains(&b':');
            out.push(AttributeOut { name: declared.name.to_vec(), value: value.to_vec(), prefixed });
        }

        if ns {
            self.expand_attribute_names(&mut out)?;
        }

        Ok((out, specified))
    }

    /// Replaces prefixed attribute names by their expanded form and rejects
    /// two attributes with the same namespace and local name.
    fn expand_attribute_names(&self, attributes: &mut [AttributeOut]) -> Result<(), ErrorCode> {
        let separator = self.ns_separator.filter(|&byte| byte != 0);
        let mut expanded: HashSet<(Rc<[u8]>, Vec<u8>)> = HashSet::new();
        for attribute in attributes.iter_mut().filter(|attribute| attribute.prefixed) {
            let colon = attribute.name.iter().position(|&byte| byte == b':').unwrap_or(0);
            let prefix = &attribute.name[..colon];
            let local = attribute.name[colon + 1..].to_vec();
            let Some(uri) = self.lookup_binding(Some(prefix)) else {
                return Err(ErrorCode::UnboundPrefix);
            };
            if !expanded.insert((Rc::clone(&uri), local.clone())) {
                return Err(ErrorCode::DuplicateAttribute);
            }

            let mut name = uri.to_vec();
            name.extend(separator);
            name.extend_from_slice(&local);
            // A NUL separator ends the reported string before the prefix.
            if self.ns_triplets && separator.is_some() {
                name.extend(separator);
                name.extend_from_slice(prefix);
            }
            attribute.name = name;
        }

        Ok(())
    }

    /// The URI bound to `prefix` (`None` for the default namespace).
    fn lookup_binding(&self, prefix: Option<&[u8]>) -> Option<Rc<[u8]>> {
        let binding = self.bindings.iter().rev().find(|binding| binding.prefix.as_deref() == prefix)?;

        binding.uri.clone()
    }

    /// The reported name of an element: the expanded name in a namespace,
    /// otherwise the name as written.
    fn expand_element_name(&self, qname: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        if self.ns_separator.is_none() {
            return Ok(qname.to_vec());
        }

        let separator = self.ns_separator.filter(|&byte| byte != 0);
        let colon = qname.iter().position(|&byte| byte == b':');
        let (uri, local, prefix) = match colon {
            Some(colon) => {
                let prefix = &qname[..colon];
                let Some(uri) = self.lookup_binding(Some(prefix)) else {
                    return Err(ErrorCode::UnboundPrefix);
                };
                (uri, &qname[colon + 1..], Some(prefix))
            }
            None => {
                let Some(uri) = self.lookup_binding(None) else {
                    return Ok(qname.to_vec());
                };
                (uri, qname, None)
            }
        };

        let mut name = uri.to_vec();
        name.extend(separator);
        name.extend_from_slice(local);
        if self.ns_triplets
            && separator.is_some()
            && let Some(prefix) = prefix
        {
            name.extend(separator);
            name.extend_from_slice(prefix);
        }

        Ok(name)
    }

    /// Applies a namespace declaration attribute `name="uri"`.
    fn declare_namespace(&mut self, callbacks: &mut dyn Callbacks, name: &[u8], uri: Vec<u8>) -> Result<(), ErrorCode> {
        let prefix: Option<Rc<[u8]>> = name.get(6..).map(Rc::from);
        if uri.is_empty() && prefix.is_some() {
            return Err(ErrorCode::UndeclaringPrefix);
        }

        let must_be_xml = prefix.as_deref() == Some(b"xml");
        if prefix.as_deref() == Some(b"xmlns") {
            return Err(ErrorCode::ReservedPrefixXmlns);
        }
        let is_xml = uri == XML_NAMESPACE;
        let is_xmlns = !must_be_xml && uri == XMLNS_NAMESPACE;
        if must_be_xml != is_xml {
            return Err(if must_be_xml { ErrorCode::ReservedPrefixXml } else { ErrorCode::ReservedNamespaceUri });
        }
        if is_xmlns {
            return Err(ErrorCode::ReservedNamespaceUri);
        }

        let uri: Option<Rc<[u8]>> = if uri.is_empty() { None } else { Some(Rc::from(uri)) };
        self.bindings.push(Binding { prefix: prefix.clone(), uri: uri.clone() });
        if let Some(callback) = self.handler(HandlerSlot::StartNamespaceDecl) {
            callbacks.start_namespace_decl(self, callback, prefix.as_deref(), uri.as_deref());
        }

        Ok(())
    }

    /// Ends the `count` most recent bindings, newest first.
    fn end_bindings(&mut self, callbacks: &mut dyn Callbacks, count: usize) {
        for _ in 0..count {
            let Some(binding) = self.bindings.pop() else {
                return;
            };
            if let Some(callback) = self.handler(HandlerSlot::EndNamespaceDecl) {
                callbacks.end_namespace_decl(self, callback, binding.prefix.as_deref());
            }
        }
    }

    /// An end tag `src[s..next]`.
    fn end_tag(&mut self, callbacks: &mut dyn Callbacks, src: &Src, s: usize, next: usize, level: Level) -> Result<Flow, ErrorCode> {
        let is_document = matches!(src, Src::Document);
        if let Level::Entity { depth } = level
            && depth == self.content.tags.len()
        {
            return Err(ErrorCode::AsyncEntity);
        }
        let Some(tag) = self.content.tags.pop() else {
            return Err(ErrorCode::AsyncEntity);
        };

        let unit = self.src_parts(src).1.unit();
        let raw_start = s + 2 * unit;
        let raw_end = self.scanner(src).name_end(raw_start);
        let raw_name = self.src_parts(src).0.get(raw_start..raw_end).unwrap_or_default();
        if raw_name != tag.raw_name.as_slice() {
            if is_document {
                self.event = Some(raw_start);
            }
            return Err(ErrorCode::TagMismatch);
        }

        if let Some(callback) = self.handler(HandlerSlot::EndElement) {
            callbacks.end_element(self, callback, &tag.name);
        } else if self.has(HandlerSlot::Default) {
            self.report_default(callbacks, src, s, next);
        }
        self.end_bindings(callbacks, tag.bindings);

        if level == Level::Document && self.content.tags.is_empty() && is_document {
            return Ok(Flow::Epilog(next));
        }

        Ok(Flow::Next(next))
    }

    /// Normalizes the attribute value `src[start..end]` into `out`: references
    /// replaced, white space turned into spaces and, unless `is_cdata`,
    /// collapsed and trimmed. `in_prolog` selects the declaration checks that
    /// apply to defaults in an ATTLIST declaration.
    pub(super) fn normalize_attribute_value(
        &mut self,
        src: &Src,
        is_cdata: bool,
        start: usize,
        end: usize,
        in_prolog: bool,
        out: &mut Vec<u8>,
    ) -> Result<(), ErrorCode> {
        struct ValueFrame {
            src: Src,
            pos: usize,
            end: usize,
            name: Option<Rc<[u8]>>,
        }

        let mut stack = vec![ValueFrame { src: src.clone(), pos: start, end, name: None }];
        let result = loop {
            let Some(frame) = stack.last() else {
                break Ok(());
            };
            let frame_src = frame.src.clone();
            let pos = frame.pos;
            let frame_end = frame.end;
            let is_document = matches!(frame_src, Src::Document);
            let scan = self.scanner(&frame_src).attribute_value(pos, frame_end);
            let next = scan.next;
            if let Some(frame) = stack.last_mut() {
                frame.pos = next;
            }
            let collapse = !is_cdata && out.last().is_none_or(|&last| last == b' ');

            match scan.tok {
                Tok::Empty => {
                    if let Some(name) = stack.pop().and_then(|frame| frame.name)
                        && let Some(entity) = self.dtd.borrow_mut().general.get_mut(&name)
                    {
                        entity.open = false;
                    }
                }
                Tok::Invalid => {
                    if is_document {
                        self.event = Some(next);
                    }
                    break Err(ErrorCode::InvalidToken);
                }
                Tok::Partial => {
                    if is_document {
                        self.event = Some(pos);
                    }
                    break Err(ErrorCode::InvalidToken);
                }
                Tok::CharRef => {
                    let (buf, enc) = self.src_parts(&frame_src);
                    let Some(code) = char_ref_value(buf, pos, next, enc) else {
                        if is_document {
                            self.event = Some(pos);
                        }
                        break Err(ErrorCode::BadCharRef);
                    };
                    if code == 0x20 && collapse {
                        continue;
                    }
                    push_utf8(code, out);
                }
                Tok::Data => {
                    let text = self.utf8(&frame_src, pos, next);
                    out.extend_from_slice(&text);
                }
                Tok::TrailingCr | Tok::AttributeSpace | Tok::Newline => {
                    if !collapse {
                        out.push(b' ');
                    }
                }
                Tok::EntityRef => {
                    let unit = self.src_parts(&frame_src).1.unit();
                    let name = self.utf8(&frame_src, pos + unit, next - unit);
                    if let Some(byte) = predefined_entity(&name) {
                        out.push(byte);
                        continue;
                    }

                    let (entity, check) = {
                        let dtd = self.dtd.borrow();
                        let check = if in_prolog {
                            !self.is_param_entity && if dtd.standalone { !self.prolog_in_internal_pe() } else { !dtd.has_param_entity_refs }
                        } else {
                            !dtd.has_param_entity_refs || dtd.standalone
                        };
                        (dtd.general.get(name.as_slice()).cloned(), check)
                    };
                    if check {
                        let Some(entity) = &entity else {
                            break Err(ErrorCode::UndefinedEntity);
                        };
                        if !entity.is_internal {
                            break Err(ErrorCode::EntityDeclaredInPe);
                        }
                    }
                    let Some(entity) = entity else {
                        continue;
                    };
                    if entity.open || self.inherited_open.iter().any(|open| **open == *name) {
                        if is_document {
                            self.event = Some(pos);
                        }
                        break Err(ErrorCode::RecursiveEntityRef);
                    }
                    if entity.notation.is_some() {
                        if is_document {
                            self.event = Some(pos);
                        }
                        break Err(ErrorCode::BinaryEntityRef);
                    }
                    let Some(text) = entity.text else {
                        if is_document {
                            self.event = Some(pos);
                        }
                        break Err(ErrorCode::AttributeExternalEntityRef);
                    };
                    let name: Rc<[u8]> = Rc::from(name);
                    if let Some(entity) = self.dtd.borrow_mut().general.get_mut(&name) {
                        entity.open = true;
                    }
                    let end = text.len();
                    stack.push(ValueFrame { src: Src::Text(text), pos: 0, end, name: Some(name) });
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
                && let Some(entity) = self.dtd.borrow_mut().general.get_mut(&name)
            {
                entity.open = false;
            }
        }
        result?;

        if !is_cdata && out.last() == Some(&b' ') {
            out.pop();
        }

        Ok(())
    }

    fn prolog_in_internal_pe(&self) -> bool {
        self.prolog.in_internal_pe()
    }
}
