//! Tokenizers for the contexts of an XML entity: the prolog, content, CDATA
//! sections, ignored conditional sections, attribute values and entity values.
//!
//! Every scanner starts at a position in a byte buffer and reports the token
//! found there together with the position after it. A token that reaches the
//! end of the available data is reported as incomplete, so the caller can wait
//! for more input; one that could only grow is marked `open`.

use super::chars::NameClass;
use super::chars::is_xml_char;
use super::encoding::Encoding;
use super::encoding::Unit;

/// A token kind. Error kinds put the offending position in `Scan::next`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Tok {
    /// A character or sequence that cannot occur here; `next` points at it.
    Invalid,
    /// The data ends inside a token.
    Partial,
    /// The data ends inside a multibyte character.
    PartialChar,
    /// No data at all.
    Empty,

    Comment,
    Pi,
    XmlDecl,
    Bom,

    StartTag,
    EmptyElement,
    EndTag,
    Data,
    Newline,
    TrailingCr,
    TrailingRsqb,
    CdataOpen,
    CdataClose,
    EntityRef,
    CharRef,

    Space,
    DeclOpen,
    InstanceStart,
    Name,
    PrefixedName,
    Nmtoken,
    NameQuestion,
    NameAsterisk,
    NamePlus,
    PoundName,
    Literal,
    OpenParen,
    CloseParen,
    CloseParenQuestion,
    CloseParenAsterisk,
    CloseParenPlus,
    Or,
    Comma,
    OpenBracket,
    CloseBracket,
    DeclClose,
    Percent,
    ParamEntityRef,
    CondSectOpen,
    CondSectClose,
    IgnoreSect,

    /// A run of space or tab characters inside an attribute value.
    AttributeSpace,
}

/// The result of a scan.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct Scan {
    pub tok: Tok,
    pub next: usize,
    /// The token ends at the end of the data and might continue in more input.
    pub open: bool,
}

impl Scan {
    fn new(tok: Tok, next: usize) -> Self {
        Self { tok, next, open: false }
    }

    fn open(tok: Tok, next: usize) -> Self {
        Self { tok, next, open: true }
    }

    fn invalid(at: usize) -> Self {
        Self::new(Tok::Invalid, at)
    }

    fn partial(at: usize) -> Self {
        Self::new(Tok::Partial, at)
    }

    fn partial_char(at: usize) -> Self {
        Self::new(Tok::PartialChar, at)
    }
}

/// The role of a character in the scanners.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    End,
    /// The data ends inside the character.
    Short,
    /// Not an XML character, or malformed bytes.
    Bad,
    NameStart,
    NameChar,
    Colon,
    Space,
    Cr,
    Lf,
    Lt,
    Amp,
    Rsqb,
    Lsqb,
    Gt,
    Quot,
    Apos,
    Equals,
    Quest,
    Excl,
    Sol,
    Semi,
    Num,
    Lpar,
    Rpar,
    Ast,
    Plus,
    Comma,
    Verbar,
    Percent,
    Minus,
    Other,
}

impl Class {
    fn is_name(self) -> bool {
        matches!(self, Self::NameStart | Self::NameChar | Self::Minus)
    }

    fn is_space(self) -> bool {
        matches!(self, Self::Space | Self::Cr | Self::Lf)
    }
}

/// A character's class together with its size in bytes.
#[derive(Clone, Copy, Debug)]
struct Look {
    class: Class,
    len: usize,
}

/// One attribute of a start tag: the name and the value between the quotes.
#[derive(Clone, Copy, Debug)]
pub(super) struct RawAttribute {
    pub name: (usize, usize),
    pub value: (usize, usize),
}

/// A scanner over `buf[..end]`.
pub(super) struct Scanner<'a> {
    buf: &'a [u8],
    end: usize,
    enc: &'a Encoding,
    /// Namespace processing: a colon separates a prefix inside names.
    ns: bool,
}

impl<'a> Scanner<'a> {
    pub(super) fn new(buf: &'a [u8], end: usize, enc: &'a Encoding, ns: bool) -> Self {
        Self { buf, end, enc, ns }
    }

    /// The end of the data for a token that starts at `start`, and whether a
    /// stray byte of an incomplete unit was dropped from it.
    fn limit(&self, start: usize) -> (usize, bool) {
        let end = self.enc.align(start, self.end);

        (end, end != self.end)
    }

    fn look(&self, pos: usize, end: usize) -> Look {
        if pos >= end {
            return Look { class: Class::End, len: 0 };
        }

        match self.enc.decode(self.buf, pos, end) {
            Unit::Malformed => Look { class: Class::Bad, len: self.enc.unit() },
            Unit::Truncated => Look { class: Class::Short, len: self.enc.unit() },
            Unit::Char { code, len } => Look { class: self.classify(code), len },
        }
    }

    fn classify(&self, code: u32) -> Class {
        if !is_xml_char(code) {
            return Class::Bad;
        }
        if code >= 0x80 {
            return match self.enc.name_class(code) {
                NameClass::Start => Class::NameStart,
                NameClass::Follow => Class::NameChar,
                NameClass::Other => Class::Other,
            };
        }

        match code as u8 {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => Class::NameStart,
            b':' if self.ns => Class::Colon,
            b':' => Class::NameStart,
            b'0'..=b'9' | b'.' => Class::NameChar,
            b'-' => Class::Minus,
            b' ' | b'\t' => Class::Space,
            b'\r' => Class::Cr,
            b'\n' => Class::Lf,
            b'<' => Class::Lt,
            b'&' => Class::Amp,
            b']' => Class::Rsqb,
            b'[' => Class::Lsqb,
            b'>' => Class::Gt,
            b'"' => Class::Quot,
            b'\'' => Class::Apos,
            b'=' => Class::Equals,
            b'?' => Class::Quest,
            b'!' => Class::Excl,
            b'/' => Class::Sol,
            b';' => Class::Semi,
            b'#' => Class::Num,
            b'(' => Class::Lpar,
            b')' => Class::Rpar,
            b'*' => Class::Ast,
            b'+' => Class::Plus,
            b',' => Class::Comma,
            b'|' => Class::Verbar,
            b'%' => Class::Percent,
            _ => Class::Other,
        }
    }

    /// The class of the character at `pos` where a name may continue. UTF-8
    /// multibyte sequences are judged by their payload bits alone, without
    /// checking that they are well formed.
    fn look_name(&self, pos: usize, end: usize) -> Look {
        if !matches!(self.enc, Encoding::Utf8) || pos >= end {
            return self.look(pos, end);
        }

        let byte = |offset: usize| u32::from(self.buf.get(pos + offset).copied().unwrap_or(0));
        let first = byte(0);
        let (len, code) = match first {
            0xC0..=0xDF => (2, ((first & 0x1F) << 6) | (byte(1) & 0x3F)),
            0xE0..=0xEF => (3, ((first & 0x0F) << 12) | ((byte(1) & 0x3F) << 6) | (byte(2) & 0x3F)),
            0xF0..=0xF4 => (4, u32::MAX),
            _ => return self.look(pos, end),
        };
        if end - pos < len {
            return Look { class: Class::Short, len };
        }

        let class = if code < 0x80 {
            match code as u8 {
                b'a'..=b'z' | b'A'..=b'Z' | b'_' | b':' => Class::NameStart,
                b'0'..=b'9' | b'.' | b'-' => Class::NameChar,
                _ => Class::Bad,
            }
        } else if (0xD800..=0xDFFF).contains(&code) || code > 0xFFFD {
            Class::Bad
        } else {
            match self.enc.name_class(code) {
                NameClass::Start => Class::NameStart,
                NameClass::Follow => Class::NameChar,
                NameClass::Other => Class::Bad,
            }
        };

        Look { class, len }
    }

    /// Whether the character at `pos`, which follows `<` in the prolog, opens
    /// the document element. Multibyte characters count without checking them.
    fn starts_instance(&self, pos: usize, end: usize) -> bool {
        match self.enc {
            Encoding::Utf8 => {
                let first = self.buf.get(pos).copied().unwrap_or(0);
                if (0xC0..=0xF4).contains(&first) {
                    return true;
                }
            }
            Encoding::Utf16 { .. } => {
                let unit = self.enc.raw_unit(self.buf, pos);
                if unit >= 0x100 {
                    return !matches!(unit, 0xDC00..=0xDFFF | 0xFFFE | 0xFFFF);
                }
            }
            _ => {}
        }

        self.look(pos, end).class == Class::NameStart
    }

    /// A data run starting at `pos` for character data in content.
    fn content_data(&self, mut pos: usize, end: usize) -> Scan {
        let unit = self.enc.unit();
        loop {
            let look = self.look(pos, end);
            match look.class {
                Class::End | Class::Lt | Class::Amp | Class::Cr | Class::Lf | Class::Bad | Class::Short => {
                    return Scan::new(Tok::Data, pos);
                }
                Class::Rsqb => {
                    // `]]>` cannot occur in content; a bracket at the end of the
                    // data waits for what follows it.
                    let second = self.look(pos + unit, end);
                    if second.class == Class::End {
                        return Scan::new(Tok::Data, pos);
                    }
                    if second.class != Class::Rsqb {
                        pos += unit;
                        continue;
                    }
                    let third = self.look(pos + 2 * unit, end);
                    if third.class == Class::End {
                        return Scan::new(Tok::Data, pos);
                    }
                    if third.class != Class::Gt {
                        pos += unit;
                        continue;
                    }
                    return Scan::invalid(pos + 2 * unit);
                }
                _ => pos += look.len,
            }
        }
    }

    /// The token at `pos` in element content.
    pub(super) fn content(&self, pos: usize) -> Scan {
        let (end, dropped) = self.limit(pos);
        if pos >= end {
            return if dropped { Scan::partial(pos) } else { Scan::new(Tok::Empty, pos) };
        }

        let unit = self.enc.unit();
        let look = self.look(pos, end);
        match look.class {
            Class::Lt => self.after_lt(pos + unit, end),
            Class::Amp => self.reference(pos + unit, end),
            Class::Cr => {
                let next = pos + unit;
                if next >= end {
                    return Scan::new(Tok::TrailingCr, next);
                }
                if self.look(next, end).class == Class::Lf {
                    return Scan::new(Tok::Newline, next + unit);
                }
                Scan::new(Tok::Newline, next)
            }
            Class::Lf => Scan::new(Tok::Newline, pos + unit),
            Class::Rsqb => {
                let second = pos + unit;
                if second >= end {
                    return Scan::new(Tok::TrailingRsqb, second);
                }
                if self.look(second, end).class != Class::Rsqb {
                    return self.content_data(second, end);
                }
                let third = second + unit;
                if third >= end {
                    return Scan::new(Tok::TrailingRsqb, third);
                }
                if self.look(third, end).class != Class::Gt {
                    return self.content_data(second, end);
                }
                Scan::invalid(third)
            }
            Class::Bad => Scan::invalid(pos),
            Class::Short => Scan::partial_char(pos),
            _ => self.content_data(pos + look.len, end),
        }
    }

    /// Markup that starts with `<` in content; `pos` follows the `<`.
    fn after_lt(&self, pos: usize, end: usize) -> Scan {
        let unit = self.enc.unit();
        let look = self.look_name(pos, end);
        match look.class {
            Class::End => Scan::partial(pos),
            Class::NameStart => self.start_tag(pos + look.len, end),
            Class::Excl => {
                let next = pos + unit;
                match self.look(next, end).class {
                    Class::End => Scan::partial(next),
                    Class::Minus => self.comment(next + unit, end),
                    Class::Lsqb => self.cdata_open(next + unit, end),
                    _ => Scan::invalid(next),
                }
            }
            Class::Quest => self.pi(pos + unit, end),
            Class::Sol => self.end_tag(pos + unit, end),
            Class::Short => Scan::partial_char(pos),
            _ => Scan::invalid(pos),
        }
    }

    /// Continues a qualified name after its first character. Returns the
    /// position of the first character that cannot continue it, or the
    /// error that ends the scan.
    fn qname_rest(&self, mut pos: usize, end: usize) -> Result<usize, Scan> {
        let mut had_colon = false;
        loop {
            let look = self.look_name(pos, end);
            match look.class {
                Class::End => return Err(Scan::partial(pos)),
                Class::Short => return Err(Scan::partial_char(pos)),
                class if class.is_name() => pos += look.len,
                Class::Colon => {
                    if had_colon {
                        return Err(Scan::invalid(pos));
                    }
                    had_colon = true;
                    pos += look.len;
                    let after = self.look_name(pos, end);
                    match after.class {
                        Class::End => return Err(Scan::partial(pos)),
                        Class::Short => return Err(Scan::partial_char(pos)),
                        Class::NameStart => pos += after.len,
                        _ => return Err(Scan::invalid(pos)),
                    }
                }
                _ => return Ok(pos),
            }
        }
    }

    /// The first character of a name at `pos`, which must start one.
    fn name_start(&self, pos: usize, end: usize) -> Result<usize, Scan> {
        let look = self.look_name(pos, end);
        match look.class {
            Class::End => Err(Scan::partial(pos)),
            Class::Short => Err(Scan::partial_char(pos)),
            Class::NameStart => Ok(pos + look.len),
            _ => Err(Scan::invalid(pos)),
        }
    }

    /// A start tag; `pos` follows the first character of the element name.
    fn start_tag(&self, pos: usize, end: usize) -> Scan {
        let unit = self.enc.unit();
        let mut pos = match self.qname_rest(pos, end) {
            Ok(pos) => pos,
            Err(scan) => return scan,
        };

        // The element name is followed by white space or the end of the tag.
        let look = self.look(pos, end);
        match look.class {
            Class::Gt => return Scan::new(Tok::StartTag, pos + unit),
            Class::Sol => return self.empty_close(pos + unit, end),
            class if class.is_space() => pos += unit,
            Class::Short => return Scan::partial_char(pos),
            _ => return Scan::invalid(pos),
        }

        loop {
            // Between attributes.
            let look = self.look_name(pos, end);
            match look.class {
                Class::End => return Scan::partial(pos),
                Class::Short => return Scan::partial_char(pos),
                class if class.is_space() => {
                    pos += unit;
                    continue;
                }
                Class::Gt => return Scan::new(Tok::StartTag, pos + unit),
                Class::Sol => return self.empty_close(pos + unit, end),
                Class::NameStart => pos += look.len,
                _ => return Scan::invalid(pos),
            }

            pos = match self.attribute(pos, end) {
                Ok(pos) => pos,
                Err(scan) => return scan,
            };

            // After the closing quote: white space or the end of the tag.
            let look = self.look(pos, end);
            match look.class {
                Class::End => return Scan::partial(pos),
                class if class.is_space() => pos += unit,
                Class::Gt => return Scan::new(Tok::StartTag, pos + unit),
                Class::Sol => return self.empty_close(pos + unit, end),
                _ => return Scan::invalid(pos),
            }
        }
    }

    /// `/>` of an empty element; `pos` follows the slash.
    fn empty_close(&self, pos: usize, end: usize) -> Scan {
        match self.look(pos, end).class {
            Class::End => Scan::partial(pos),
            Class::Gt => Scan::new(Tok::EmptyElement, pos + self.enc.unit()),
            _ => Scan::invalid(pos),
        }
    }

    /// One attribute after the first character of its name; returns the
    /// position after the closing quote.
    fn attribute(&self, pos: usize, end: usize) -> Result<usize, Scan> {
        let unit = self.enc.unit();
        let mut pos = self.qname_rest(pos, end)?;

        // White space, then `=`.
        loop {
            let look = self.look(pos, end);
            match look.class {
                Class::End => return Err(Scan::partial(pos)),
                Class::Equals => {
                    pos += unit;
                    break;
                }
                class if class.is_space() => pos += unit,
                _ => return Err(Scan::invalid(pos)),
            }
        }

        // White space, then the opening quote.
        let quote = loop {
            let look = self.look(pos, end);
            match look.class {
                Class::End => return Err(Scan::partial(pos)),
                Class::Quot | Class::Apos => {
                    pos += unit;
                    break look.class;
                }
                class if class.is_space() => pos += unit,
                _ => return Err(Scan::invalid(pos)),
            }
        };

        loop {
            let look = self.look(pos, end);
            match look.class {
                Class::End => return Err(Scan::partial(pos)),
                Class::Short => return Err(Scan::partial_char(pos)),
                Class::Bad | Class::Lt => return Err(Scan::invalid(pos)),
                Class::Amp => {
                    let scan = self.reference(pos + unit, end);
                    match scan.tok {
                        Tok::EntityRef | Tok::CharRef => pos = scan.next,
                        _ => return Err(scan),
                    }
                }
                class if class == quote => return Ok(pos + unit),
                _ => pos += look.len,
            }
        }
    }

    /// An end tag; `pos` follows `</`. Colons are not checked: the name must
    /// match the start tag anyway.
    fn end_tag(&self, pos: usize, end: usize) -> Scan {
        let unit = self.enc.unit();
        let mut pos = match self.name_start(pos, end) {
            Ok(pos) => pos,
            Err(scan) => return scan,
        };

        loop {
            let look = self.look_name(pos, end);
            match look.class {
                Class::End => return Scan::partial(pos),
                Class::Short => return Scan::partial_char(pos),
                class if class.is_name() || class == Class::Colon => pos += look.len,
                class if class.is_space() => {
                    pos += unit;
                    loop {
                        match self.look(pos, end).class {
                            Class::End => return Scan::partial(pos),
                            class if class.is_space() => pos += unit,
                            Class::Gt => return Scan::new(Tok::EndTag, pos + unit),
                            _ => return Scan::invalid(pos),
                        }
                    }
                }
                Class::Gt => return Scan::new(Tok::EndTag, pos + unit),
                _ => return Scan::invalid(pos),
            }
        }
    }

    /// A reference; `pos` follows the `&`.
    fn reference(&self, pos: usize, end: usize) -> Scan {
        let unit = self.enc.unit();
        let look = self.look_name(pos, end);
        match look.class {
            Class::End => return Scan::partial(pos),
            Class::Short => return Scan::partial_char(pos),
            Class::Num => return self.char_ref(pos + unit, end),
            Class::NameStart => {}
            _ => return Scan::invalid(pos),
        }

        let mut pos = pos + look.len;
        loop {
            let look = self.look_name(pos, end);
            match look.class {
                Class::End => return Scan::partial(pos),
                Class::Short => return Scan::partial_char(pos),
                class if class.is_name() => pos += look.len,
                Class::Semi => return Scan::new(Tok::EntityRef, pos + unit),
                _ => return Scan::invalid(pos),
            }
        }
    }

    /// A character reference; `pos` follows `&#`.
    fn char_ref(&self, pos: usize, end: usize) -> Scan {
        let unit = self.enc.unit();
        let is_x = |pos: usize| self.enc.raw_unit(self.buf, pos) == u32::from(b'x');
        let is_digit = |pos: usize, hex: bool| {
            let code = self.enc.raw_unit(self.buf, pos);
            let Ok(byte) = u8::try_from(code) else {
                return false;
            };
            if hex { byte.is_ascii_hexdigit() } else { byte.is_ascii_digit() }
        };

        if pos >= end {
            return Scan::partial(pos);
        }
        let (hex, mut pos) = if is_x(pos) { (true, pos + unit) } else { (false, pos) };
        if pos >= end {
            return Scan::partial(pos);
        }
        if !is_digit(pos, hex) {
            return Scan::invalid(pos);
        }

        pos += unit;
        loop {
            if pos >= end {
                return Scan::partial(pos);
            }
            if is_digit(pos, hex) {
                pos += unit;
                continue;
            }
            if self.look(pos, end).class == Class::Semi {
                return Scan::new(Tok::CharRef, pos + unit);
            }
            return Scan::invalid(pos);
        }
    }

    /// A comment; `pos` follows `<!-`.
    fn comment(&self, pos: usize, end: usize) -> Scan {
        let unit = self.enc.unit();
        match self.look(pos, end).class {
            Class::End => return Scan::partial(pos),
            Class::Minus => {}
            _ => return Scan::invalid(pos),
        }

        let mut pos = pos + unit;
        loop {
            let look = self.look(pos, end);
            match look.class {
                Class::End => return Scan::partial(pos),
                Class::Short => return Scan::partial_char(pos),
                Class::Bad => return Scan::invalid(pos),
                Class::Minus => {
                    pos += unit;
                    match self.look(pos, end).class {
                        Class::End => return Scan::partial(pos),
                        Class::Minus => {}
                        _ => continue,
                    }
                    pos += unit;
                    match self.look(pos, end).class {
                        Class::End => return Scan::partial(pos),
                        Class::Gt => return Scan::new(Tok::Comment, pos + unit),
                        _ => return Scan::invalid(pos),
                    }
                }
                _ => pos += look.len,
            }
        }
    }

    /// `CDATA[` after `<![`; all six characters must be present first.
    fn cdata_open(&self, pos: usize, end: usize) -> Scan {
        let unit = self.enc.unit();
        if end - pos < 6 * unit {
            return Scan::partial(pos);
        }

        for (index, expected) in b"CDATA[".iter().enumerate() {
            let at = pos + index * unit;
            if self.enc.raw_unit(self.buf, at) != u32::from(*expected) {
                return Scan::invalid(at);
            }
        }

        Scan::new(Tok::CdataOpen, pos + 6 * unit)
    }

    /// A processing instruction; `pos` follows `<?`.
    fn pi(&self, pos: usize, end: usize) -> Scan {
        let unit = self.enc.unit();
        let target = pos;
        let mut pos = match self.name_start(pos, end) {
            Ok(pos) => pos,
            Err(scan) => return scan,
        };

        loop {
            let look = self.look_name(pos, end);
            match look.class {
                Class::End => return Scan::partial(pos),
                Class::Short => return Scan::partial_char(pos),
                class if class.is_name() => pos += look.len,
                class if class.is_space() => {
                    let Some(tok) = self.pi_target_kind(target, pos) else {
                        return Scan::invalid(pos);
                    };
                    pos += unit;
                    loop {
                        let look = self.look(pos, end);
                        match look.class {
                            Class::End => return Scan::partial(pos),
                            Class::Short => return Scan::partial_char(pos),
                            Class::Bad => return Scan::invalid(pos),
                            Class::Quest => {
                                pos += unit;
                                match self.look(pos, end).class {
                                    Class::End => return Scan::partial(pos),
                                    Class::Gt => return Scan::new(tok, pos + unit),
                                    _ => {}
                                }
                            }
                            _ => pos += look.len,
                        }
                    }
                }
                Class::Quest => {
                    let Some(tok) = self.pi_target_kind(target, pos) else {
                        return Scan::invalid(pos);
                    };
                    pos += unit;
                    return match self.look(pos, end).class {
                        Class::End => Scan::partial(pos),
                        Class::Gt => Scan::new(tok, pos + unit),
                        _ => Scan::invalid(pos),
                    };
                }
                _ => return Scan::invalid(pos),
            }
        }
    }

    /// `Pi`, or `XmlDecl` for the target `xml`; `None` for other spellings of
    /// `xml`, which are reserved.
    fn pi_target_kind(&self, start: usize, end: usize) -> Option<Tok> {
        let unit = self.enc.unit();
        if end - start != 3 * unit {
            return Some(Tok::Pi);
        }

        let mut upper = false;
        for (index, letter) in b"xml".iter().enumerate() {
            let code = self.enc.raw_unit(self.buf, start + index * unit);
            if code == u32::from(*letter) {
                continue;
            }
            if code == u32::from(letter.to_ascii_uppercase()) {
                upper = true;
                continue;
            }
            return Some(Tok::Pi);
        }

        if upper { None } else { Some(Tok::XmlDecl) }
    }

    /// The token at `pos` inside a CDATA section.
    pub(super) fn cdata(&self, pos: usize) -> Scan {
        let unit = self.enc.unit();
        let (end, dropped) = self.limit(pos);
        if pos >= end {
            return if dropped { Scan::partial(pos) } else { Scan::new(Tok::Empty, pos) };
        }

        let look = self.look(pos, end);
        let data_from = match look.class {
            Class::Rsqb => {
                let second = pos + unit;
                match self.look(second, end).class {
                    Class::End => return Scan::partial(second),
                    Class::Rsqb => {
                        let third = second + unit;
                        match self.look(third, end).class {
                            Class::End => return Scan::partial(third),
                            Class::Gt => return Scan::new(Tok::CdataClose, third + unit),
                            _ => second,
                        }
                    }
                    _ => second,
                }
            }
            Class::Cr => {
                let next = pos + unit;
                return match self.look(next, end).class {
                    Class::End => Scan::partial(next),
                    Class::Lf => Scan::new(Tok::Newline, next + unit),
                    _ => Scan::new(Tok::Newline, next),
                };
            }
            Class::Lf => return Scan::new(Tok::Newline, pos + unit),
            Class::Bad => return Scan::invalid(pos),
            Class::Short => return Scan::partial_char(pos),
            _ => pos + look.len,
        };

        let mut pos = data_from;
        loop {
            let look = self.look(pos, end);
            match look.class {
                Class::End | Class::Short | Class::Bad | Class::Cr | Class::Lf | Class::Rsqb => {
                    return Scan::new(Tok::Data, pos);
                }
                _ => pos += look.len,
            }
        }
    }

    /// The rest of an ignored conditional section, nested sections included;
    /// `IgnoreSect` ends after its closing `]]>`.
    pub(super) fn ignore_section(&self, pos: usize) -> Scan {
        let unit = self.enc.unit();
        let (end, _) = self.limit(pos);
        let mut depth = 0usize;
        let mut pos = pos;
        loop {
            let look = self.look(pos, end);
            match look.class {
                Class::End => return Scan::partial(pos),
                Class::Short => return Scan::partial_char(pos),
                Class::Bad => return Scan::invalid(pos),
                Class::Lt => {
                    pos += unit;
                    match self.look(pos, end).class {
                        Class::End => return Scan::partial(pos),
                        Class::Excl => {}
                        _ => continue,
                    }
                    pos += unit;
                    match self.look(pos, end).class {
                        Class::End => return Scan::partial(pos),
                        Class::Lsqb => {
                            depth += 1;
                            pos += unit;
                        }
                        _ => {}
                    }
                }
                Class::Rsqb => {
                    pos += unit;
                    match self.look(pos, end).class {
                        Class::End => return Scan::partial(pos),
                        Class::Rsqb => {}
                        _ => continue,
                    }
                    pos += unit;
                    match self.look(pos, end).class {
                        Class::End => return Scan::partial(pos),
                        Class::Gt => {
                            pos += unit;
                            if depth == 0 {
                                return Scan::new(Tok::IgnoreSect, pos);
                            }
                            depth -= 1;
                        }
                        _ => {}
                    }
                }
                _ => pos += look.len,
            }
        }
    }

    /// The token at `pos` in the prolog or a DTD.
    pub(super) fn prolog(&self, pos: usize) -> Scan {
        let unit = self.enc.unit();
        let (end, dropped) = self.limit(pos);
        if pos >= end {
            return if dropped { Scan::partial(pos) } else { Scan::new(Tok::Empty, pos) };
        }

        let look = self.look_name(pos, end);
        match look.class {
            Class::Quot | Class::Apos => self.literal(pos + unit, end, look.class),
            Class::Lt => {
                let next = pos + unit;
                match self.look(next, end).class {
                    Class::End => Scan::partial(next),
                    Class::Excl => self.declaration(next + unit, end),
                    Class::Quest => self.pi(next + unit, end),
                    _ if self.starts_instance(next, end) => Scan::new(Tok::InstanceStart, pos),
                    _ => Scan::invalid(next),
                }
            }
            Class::Cr if pos + unit >= end => Scan::open(Tok::Space, end),
            class if class.is_space() => self.prolog_space(pos + unit, end),
            Class::Percent => self.percent(pos + unit, end),
            Class::Lpar => Scan::new(Tok::OpenParen, pos + unit),
            Class::Rpar => self.close_paren(pos + unit, end),
            Class::Verbar => Scan::new(Tok::Or, pos + unit),
            Class::Comma => Scan::new(Tok::Comma, pos + unit),
            Class::Lsqb => Scan::new(Tok::OpenBracket, pos + unit),
            Class::Rsqb => {
                let next = pos + unit;
                match self.look(next, end).class {
                    Class::End => Scan::open(Tok::CloseBracket, next),
                    Class::Rsqb => {
                        let third = next + unit;
                        match self.look(third, end).class {
                            Class::End => Scan::partial(third),
                            Class::Gt => Scan::new(Tok::CondSectClose, third + unit),
                            _ => Scan::new(Tok::CloseBracket, next),
                        }
                    }
                    _ => Scan::new(Tok::CloseBracket, next),
                }
            }
            Class::Gt => Scan::new(Tok::DeclClose, pos + unit),
            Class::Num => self.pound_name(pos + unit, end),
            Class::NameStart => self.prolog_name(pos + look.len, end, Tok::Name),
            Class::NameChar | Class::Minus | Class::Colon => self.prolog_name(pos + look.len, end, Tok::Nmtoken),
            Class::Short => Scan::partial_char(pos),
            _ => Scan::invalid(pos),
        }
    }

    /// White space in the prolog after its first character. A carriage return
    /// at the end of the data stays for the next token, which may pair it with
    /// a line feed.
    fn prolog_space(&self, mut pos: usize, end: usize) -> Scan {
        let unit = self.enc.unit();
        loop {
            match self.look(pos, end).class {
                Class::Space | Class::Lf => pos += unit,
                Class::Cr if pos + unit < end => pos += unit,
                _ => return Scan::new(Tok::Space, pos),
            }
        }
    }

    /// `<!` markup in the prolog; `pos` follows `<!`.
    fn declaration(&self, pos: usize, end: usize) -> Scan {
        let unit = self.enc.unit();
        match self.look(pos, end).class {
            Class::End => return Scan::partial(pos),
            Class::Minus => return self.comment(pos + unit, end),
            Class::Lsqb => return Scan::new(Tok::CondSectOpen, pos + unit),
            Class::NameStart if self.is_table_char(pos) => {}
            _ => return Scan::invalid(pos),
        }

        let mut pos = pos + unit;
        loop {
            match self.look(pos, end).class {
                Class::End => return Scan::partial(pos),
                Class::NameStart if self.is_table_char(pos) => pos += unit,
                Class::Percent => {
                    return match self.look(pos + unit, end).class {
                        Class::End => Scan::partial(pos + unit),
                        class if class.is_space() || class == Class::Percent => Scan::invalid(pos),
                        _ => Scan::new(Tok::DeclOpen, pos),
                    };
                }
                class if class.is_space() => return Scan::new(Tok::DeclOpen, pos),
                _ => return Scan::invalid(pos),
            }
        }
    }

    /// Whether the character at `pos` is one the encoding classifies through
    /// its single-unit table: ASCII for UTF-8, Latin-1 for UTF-16, and every
    /// character for the single-byte encodings.
    fn is_table_char(&self, pos: usize) -> bool {
        let code = self.enc.raw_unit(self.buf, pos);
        match self.enc {
            Encoding::Utf8 => code < 0x80,
            Encoding::Utf16 { .. } => code < 0x100,
            _ => true,
        }
    }

    /// A quoted literal; `pos` follows the opening quote.
    fn literal(&self, mut pos: usize, end: usize, quote: Class) -> Scan {
        let unit = self.enc.unit();
        loop {
            let look = self.look(pos, end);
            match look.class {
                Class::End => return Scan::partial(pos),
                Class::Short => return Scan::partial_char(pos),
                Class::Bad => return Scan::invalid(pos),
                class if class == quote => {
                    pos += unit;
                    return match self.look(pos, end).class {
                        Class::End => Scan::open(Tok::Literal, pos),
                        Class::Space | Class::Cr | Class::Lf | Class::Gt | Class::Percent | Class::Lsqb => Scan::new(Tok::Literal, pos),
                        _ => Scan::invalid(pos),
                    };
                }
                _ => pos += look.len,
            }
        }
    }

    /// `%` in the prolog: a parameter entity reference or the marker of a
    /// parameter entity declaration; `pos` follows the `%`.
    fn percent(&self, pos: usize, end: usize) -> Scan {
        let look = self.look_name(pos, end);
        match look.class {
            Class::End => return Scan::partial(pos),
            Class::Short => return Scan::partial_char(pos),
            class if class.is_space() || class == Class::Percent => {
                return Scan::new(Tok::Percent, pos);
            }
            Class::NameStart => {}
            _ => return Scan::invalid(pos),
        }

        let mut pos = pos + look.len;
        loop {
            let look = self.look_name(pos, end);
            match look.class {
                Class::End => return Scan::partial(pos),
                Class::Short => return Scan::partial_char(pos),
                class if class.is_name() => pos += look.len,
                Class::Semi => return Scan::new(Tok::ParamEntityRef, pos + self.enc.unit()),
                _ => return Scan::invalid(pos),
            }
        }
    }

    /// `)` with an optional occurrence suffix; `pos` follows the `)`.
    fn close_paren(&self, pos: usize, end: usize) -> Scan {
        let unit = self.enc.unit();
        match self.look(pos, end).class {
            Class::End => Scan::open(Tok::CloseParen, pos),
            Class::Quest => Scan::new(Tok::CloseParenQuestion, pos + unit),
            Class::Ast => Scan::new(Tok::CloseParenAsterisk, pos + unit),
            Class::Plus => Scan::new(Tok::CloseParenPlus, pos + unit),
            Class::Space | Class::Cr | Class::Lf | Class::Gt | Class::Comma | Class::Verbar | Class::Rpar => Scan::new(Tok::CloseParen, pos),
            _ => Scan::invalid(pos),
        }
    }

    /// `#NAME`; `pos` follows the `#`.
    fn pound_name(&self, pos: usize, end: usize) -> Scan {
        let mut pos = match self.name_start(pos, end) {
            Ok(pos) => pos,
            Err(scan) => return scan,
        };

        loop {
            let look = self.look_name(pos, end);
            match look.class {
                Class::End => return Scan::open(Tok::PoundName, pos),
                Class::Short => return Scan::partial_char(pos),
                class if class.is_name() => pos += look.len,
                Class::Space | Class::Cr | Class::Lf | Class::Rpar | Class::Gt | Class::Percent | Class::Verbar => {
                    return Scan::new(Tok::PoundName, pos);
                }
                _ => return Scan::invalid(pos),
            }
        }
    }

    /// A name or name token in the prolog after its first character.
    fn prolog_name(&self, mut pos: usize, end: usize, mut tok: Tok) -> Scan {
        let unit = self.enc.unit();
        loop {
            let look = self.look_name(pos, end);
            match look.class {
                Class::End => return Scan::open(tok, pos),
                Class::Short => return Scan::partial_char(pos),
                class if class.is_name() => pos += look.len,
                Class::Gt | Class::Rpar | Class::Comma | Class::Verbar | Class::Lsqb | Class::Percent | Class::Space | Class::Cr | Class::Lf => {
                    return Scan::new(tok, pos);
                }
                Class::Colon => {
                    pos += unit;
                    tok = match tok {
                        Tok::Name => {
                            let after = self.look_name(pos, end);
                            match after.class {
                                Class::End => return Scan::partial(pos),
                                Class::Short => return Scan::partial_char(pos),
                                class if class.is_name() => Tok::PrefixedName,
                                _ if !self.is_table_char(pos) => return Scan::invalid(pos),
                                _ => Tok::Nmtoken,
                            }
                        }
                        Tok::PrefixedName => Tok::Nmtoken,
                        other => other,
                    };
                }
                Class::Plus | Class::Ast | Class::Quest => {
                    if tok == Tok::Nmtoken {
                        return Scan::invalid(pos);
                    }
                    let suffixed = match look.class {
                        Class::Plus => Tok::NamePlus,
                        Class::Ast => Tok::NameAsterisk,
                        _ => Tok::NameQuestion,
                    };
                    return Scan::new(suffixed, pos + unit);
                }
                _ => return Scan::invalid(pos),
            }
        }
    }

    /// The token at `pos` inside an attribute value (`<` is never allowed).
    pub(super) fn attribute_value(&self, pos: usize, end: usize) -> Scan {
        let unit = self.enc.unit();
        if pos >= end {
            return Scan::new(Tok::Empty, pos);
        }

        let look = self.look(pos, end);
        match look.class {
            Class::Amp => return self.reference(pos + unit, end),
            Class::Lt => return Scan::invalid(pos),
            Class::Cr => {
                let next = pos + unit;
                if next >= end {
                    return Scan::new(Tok::TrailingCr, next);
                }
                if self.look(next, end).class == Class::Lf {
                    return Scan::new(Tok::Newline, next + unit);
                }
                return Scan::new(Tok::Newline, next);
            }
            Class::Lf => return Scan::new(Tok::Newline, pos + unit),
            Class::Space => return Scan::new(Tok::AttributeSpace, pos + unit),
            Class::Bad => return Scan::invalid(pos),
            Class::Short => return Scan::partial_char(pos),
            _ => {}
        }

        let mut pos = pos + look.len;
        loop {
            let look = self.look(pos, end);
            match look.class {
                Class::End | Class::Amp | Class::Lt | Class::Cr | Class::Lf | Class::Space | Class::Bad | Class::Short => {
                    return Scan::new(Tok::Data, pos);
                }
                _ => pos += look.len,
            }
        }
    }

    /// The token at `pos` inside an entity value.
    pub(super) fn entity_value(&self, pos: usize, end: usize) -> Scan {
        let unit = self.enc.unit();
        if pos >= end {
            return Scan::new(Tok::Empty, pos);
        }

        let look = self.look(pos, end);
        match look.class {
            Class::Amp => return self.reference(pos + unit, end),
            Class::Percent => {
                let scan = self.percent(pos + unit, end);
                return if scan.tok == Tok::Percent { Scan::invalid(scan.next) } else { scan };
            }
            Class::Cr => {
                let next = pos + unit;
                if next >= end {
                    return Scan::new(Tok::TrailingCr, next);
                }
                if self.look(next, end).class == Class::Lf {
                    return Scan::new(Tok::Newline, next + unit);
                }
                return Scan::new(Tok::Newline, next);
            }
            Class::Lf => return Scan::new(Tok::Newline, pos + unit),
            Class::Bad => return Scan::invalid(pos),
            Class::Short => return Scan::partial_char(pos),
            _ => {}
        }

        let mut pos = pos + look.len;
        loop {
            let look = self.look(pos, end);
            match look.class {
                Class::End | Class::Amp | Class::Percent | Class::Cr | Class::Lf | Class::Bad | Class::Short => {
                    return Scan::new(Tok::Data, pos);
                }
                _ => pos += look.len,
            }
        }
    }

    /// The span of the name that starts at `pos` and runs while characters
    /// can continue a name or are colons.
    pub(super) fn name_end(&self, mut pos: usize) -> usize {
        loop {
            let look = self.look_name(pos, self.end);
            match look.class {
                class if class.is_name() || class == Class::Colon => pos += look.len,
                _ => return pos,
            }
        }
    }

    /// The position of the first character at or after `pos` that is not
    /// white space.
    pub(super) fn skip_space(&self, mut pos: usize) -> usize {
        while self.look(pos, self.end).class.is_space() {
            pos += self.enc.unit();
        }

        pos
    }

    /// The attributes of a well-formed start tag that starts at `start` with `<`.
    pub(super) fn attributes(&self, start: usize, out: &mut Vec<RawAttribute>) {
        let unit = self.enc.unit();
        out.clear();

        let mut pos = self.name_end(start + unit);
        loop {
            pos = self.skip_space(pos);
            if !self.look_name(pos, self.end).class.is_name() {
                return;
            }

            let name_end = self.name_end(pos);
            let mut value = self.skip_space(name_end) + unit;
            value = self.skip_space(value);
            let quote = self.enc.raw_unit(self.buf, value);
            let value_start = value + unit;
            let mut value_end = value_start;
            while value_end < self.end && self.enc.raw_unit(self.buf, value_end) != quote {
                value_end += self.look(value_end, self.end).len.max(unit);
            }

            out.push(RawAttribute { name: (pos, name_end), value: (value_start, value_end) });
            pos = value_end + unit;
        }
    }
}
