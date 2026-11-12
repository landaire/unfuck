//! The tokenizer of CPython 2.7.12 for string input:
//! newline translation, the UTF-8 BOM, coding declarations, and tokens with
//! indentation tracking.

use crate::interp::compiler::source::SourceEncoding;

pub const ENDMARKER: u16 = 0;
pub const NAME: u16 = 1;
pub const NUMBER: u16 = 2;
pub const STRING: u16 = 3;
pub const NEWLINE: u16 = 4;
pub const INDENT: u16 = 5;
pub const DEDENT: u16 = 6;
pub const LPAR: u16 = 7;
pub const RPAR: u16 = 8;
pub const LSQB: u16 = 9;
pub const RSQB: u16 = 10;
pub const COLON: u16 = 11;
pub const COMMA: u16 = 12;
pub const SEMI: u16 = 13;
pub const PLUS: u16 = 14;
pub const MINUS: u16 = 15;
pub const STAR: u16 = 16;
pub const SLASH: u16 = 17;
pub const VBAR: u16 = 18;
pub const AMPER: u16 = 19;
pub const LESS: u16 = 20;
pub const GREATER: u16 = 21;
pub const EQUAL: u16 = 22;
pub const DOT: u16 = 23;
pub const PERCENT: u16 = 24;
pub const BACKQUOTE: u16 = 25;
pub const LBRACE: u16 = 26;
pub const RBRACE: u16 = 27;
pub const EQEQUAL: u16 = 28;
pub const NOTEQUAL: u16 = 29;
pub const LESSEQUAL: u16 = 30;
pub const GREATEREQUAL: u16 = 31;
pub const TILDE: u16 = 32;
pub const CIRCUMFLEX: u16 = 33;
pub const LEFTSHIFT: u16 = 34;
pub const RIGHTSHIFT: u16 = 35;
pub const DOUBLESTAR: u16 = 36;
pub const PLUSEQUAL: u16 = 37;
pub const MINEQUAL: u16 = 38;
pub const STAREQUAL: u16 = 39;
pub const SLASHEQUAL: u16 = 40;
pub const PERCENTEQUAL: u16 = 41;
pub const AMPEREQUAL: u16 = 42;
pub const VBAREQUAL: u16 = 43;
pub const CIRCUMFLEXEQUAL: u16 = 44;
pub const LEFTSHIFTEQUAL: u16 = 45;
pub const RIGHTSHIFTEQUAL: u16 = 46;
pub const DOUBLESTAREQUAL: u16 = 47;
pub const DOUBLESLASH: u16 = 48;
pub const DOUBLESLASHEQUAL: u16 = 49;
pub const AT: u16 = 50;
pub const OP: u16 = 51;
pub const ERRORTOKEN: u16 = 52;

/// Nonterminal symbol numbers start here.
pub const NT_OFFSET: u16 = 256;

const TABSIZE: usize = 8;
const MAXINDENT: usize = 100;

/// Why the tokenizer stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    /// End of input.
    Eof,
    /// An invalid token.
    BadToken,
    /// Indentation nested too deep.
    TooDeep,
    /// A dedent that matches no outer indentation level.
    Dedent,
    /// End of input inside a triple-quoted string.
    EofInTripleQuoted,
    /// End of line inside a single-quoted string.
    EolInString,
    /// End of input after a line continuation.
    LineContinuation,
}

/// A token: its type and the byte range of its text in the buffer.
/// INDENT, DEDENT, and ENDMARKER have no text.
#[derive(Clone, Copy, Debug)]
pub struct Token {
    pub kind: u16,
    pub span: Option<(usize, usize)>,
}

/// Source text prepared for tokenizing: newlines translated, the BOM
/// removed, and the text recoded to UTF-8 when a coding declaration names
/// an encoding other than UTF-8 and Latin-1.
pub struct PreparedSource {
    pub text: Vec<u8>,
    pub encoding: Option<SourceEncoding>,
}

/// Tokenizer state for a string. Positions are byte offsets into `text`.
pub struct Tokenizer<'a> {
    text: &'a [u8],

    /// Start of the line holding the current token's start.
    line_buffer: usize,
    cur: usize,
    inp: usize,
    start: Option<usize>,
    line_start: usize,

    pub done: Status,
    pub lineno: i32,
    tabsize: usize,
    indent: usize,
    indstack: [usize; MAXINDENT],
    atbol: bool,
    pendin: i32,
    level: i32,
    cont_line: bool,
}

impl<'a> Tokenizer<'a> {
    pub fn new(text: &'a [u8]) -> Self {
        Self {
            text,
            line_buffer: 0,
            cur: 0,
            inp: 0,
            start: None,
            line_start: 0,
            done: Status::Ok,
            lineno: 0,
            tabsize: TABSIZE,
            indent: 0,
            indstack: [0; MAXINDENT],
            atbol: true,
            pendin: 0,
            level: 0,
            cont_line: false,
        }
    }

    /// Start of the current line.
    pub fn line_start(&self) -> usize {
        self.line_start
    }

    /// The error offset the parser reports, from the start of the line.
    pub fn error_offset(&self) -> usize {
        self.cur - self.line_buffer
    }

    /// The error text the parser reports: the line read so far.
    pub fn error_line(&self) -> &'a [u8] {
        &self.text[self.line_buffer..self.inp]
    }

    pub fn indent(&self) -> usize {
        self.indent
    }

    /// Queues dedents back to column zero, as the parser does at the end of
    /// input.
    pub fn imply_dedents(&mut self) {
        self.pendin = -(self.indent as i32);
        self.indent = 0;
    }

    /// The next input character, or `None` at the end.
    fn next_char(&mut self) -> Option<u8> {
        if self.cur != self.inp {
            let byte = self.text[self.cur];
            self.cur += 1;
            return Some(byte);
        }

        if self.done != Status::Ok {
            return None;
        }

        let end = match self.text[self.inp..].iter().position(|&byte| byte == b'\n') {
            Some(newline) => self.inp + newline + 1,
            None if self.inp == self.text.len() => {
                self.done = Status::Eof;
                return None;
            }
            None => self.text.len(),
        };

        if self.start.is_none() {
            self.line_buffer = self.cur;
        }
        self.line_start = self.cur;
        self.lineno += 1;
        self.inp = end;

        let byte = self.text[self.cur];
        self.cur += 1;

        Some(byte)
    }

    /// Returns `byte` to the input.
    fn backup(&mut self, byte: Option<u8>) {
        if byte.is_some() {
            self.cur -= 1;
        }
    }

    fn token(&self, kind: u16) -> Token {
        let span = self.start.map(|start| (start, self.cur));
        Token { kind, span }
    }

    fn error(&mut self, status: Status) -> Token {
        self.done = status;
        self.cur = self.inp;

        Token { kind: ERRORTOKEN, span: None }
    }

    /// The next token.
    pub fn next_token(&mut self) -> Token {
        let mut blankline;

        'nextline: loop {
            self.start = None;
            blankline = false;

            if self.atbol {
                self.atbol = false;
                let mut col = 0usize;
                let c = loop {
                    let c = self.next_char();
                    match c {
                        Some(b' ') => col += 1,
                        Some(b'\t') => col = (col / self.tabsize + 1) * self.tabsize,
                        Some(b'\x0c') => col = 0,
                        _ => break c,
                    }
                };
                self.backup(c);

                // Lines holding only whitespace or a comment do not affect
                // indentation and produce no NEWLINE.
                if c == Some(b'#') || c == Some(b'\n') {
                    blankline = true;
                }

                if !blankline && self.level == 0 {
                    let current = self.indstack[self.indent];
                    if col > current {
                        if self.indent + 1 >= MAXINDENT {
                            return self.error(Status::TooDeep);
                        }
                        self.pendin += 1;
                        self.indent += 1;
                        self.indstack[self.indent] = col;
                    } else if col < current {
                        while self.indent > 0 && col < self.indstack[self.indent] {
                            self.pendin -= 1;
                            self.indent -= 1;
                        }
                        if col != self.indstack[self.indent] {
                            return self.error(Status::Dedent);
                        }
                    }
                }
            }

            self.start = Some(self.cur);

            if self.pendin != 0 {
                let kind = if self.pendin < 0 {
                    self.pendin += 1;
                    DEDENT
                } else {
                    self.pendin -= 1;
                    INDENT
                };
                return Token { kind, span: None };
            }

            'again: loop {
                self.start = None;
                let mut c = loop {
                    let c = self.next_char();
                    if !matches!(c, Some(b' ' | b'\t' | b'\x0c')) {
                        break c;
                    }
                };

                self.start = Some(self.cur - usize::from(c.is_some()));

                if c == Some(b'#') {
                    c = self.skip_comment();
                }

                let Some(byte) = c else {
                    if self.done == Status::Eof {
                        return Token { kind: ENDMARKER, span: None };
                    }
                    return Token { kind: ERRORTOKEN, span: None };
                };

                if byte.is_ascii_alphabetic() || byte == b'_' {
                    return self.name_or_prefixed_string(byte);
                }

                if byte == b'\n' {
                    self.atbol = true;
                    if blankline || self.level > 0 {
                        continue 'nextline;
                    }
                    self.cont_line = false;
                    let start = self.start.unwrap_or(self.cur);
                    return Token { kind: NEWLINE, span: Some((start, self.cur - 1)) };
                }

                if byte == b'.' {
                    let next = self.next_char();
                    if next.is_some_and(|digit| digit.is_ascii_digit()) {
                        return self.number_fraction();
                    }
                    self.backup(next);
                    return self.token(DOT);
                }

                if byte.is_ascii_digit() {
                    return self.number(byte);
                }

                if byte == b'\'' || byte == b'"' {
                    return self.string(byte);
                }

                if byte == b'\\' {
                    let next = self.next_char();
                    if next != Some(b'\n') {
                        return self.error(Status::LineContinuation);
                    }
                    self.cont_line = true;
                    continue 'again;
                }

                return self.operator(byte);
            }
        }
    }

    /// Skips a comment, honoring the editor tab-size settings the tokenizer
    /// recognizes. Returns the character that ends it.
    fn skip_comment(&mut self) -> Option<u8> {
        const TAB_FORMS: [&[u8]; 4] = [b"tab-width:", b":tabstop=", b":ts=", b"set tabsize="];
        const COMMENT_BUFFER: usize = 80;

        // The comment's first 79 bytes are kept, with EOF
        // stored as the byte 0xFF as C's `char` conversion does.
        let mut comment = Vec::with_capacity(COMMENT_BUFFER);
        let mut c;
        loop {
            c = self.next_char();
            comment.push(c.unwrap_or(0xff));
            if c.is_none() || c == Some(b'\n') || comment.len() + 1 >= COMMENT_BUFFER {
                break;
            }
        }

        for form in TAB_FORMS {
            let Some(found) = comment.windows(form.len()).position(|window| window == form) else {
                continue;
            };
            let size = c_atoi(&comment[found + form.len()..]);
            if (1..=40).contains(&size) {
                self.tabsize = size as usize;
            }
        }

        while c.is_some() && c != Some(b'\n') {
            c = self.next_char();
        }

        c
    }

    fn name_or_prefixed_string(&mut self, first: u8) -> Token {
        let mut c = self.next_char();
        match first {
            b'b' | b'B' | b'u' | b'U' => {
                if matches!(c, Some(b'r' | b'R')) {
                    c = self.next_char();
                }
                if let Some(quote @ (b'"' | b'\'')) = c {
                    return self.string(quote);
                }
            }
            b'r' | b'R' => {
                if let Some(quote @ (b'"' | b'\'')) = c {
                    return self.string(quote);
                }
            }
            _ => {}
        }

        while let Some(byte) = c {
            if !(byte.is_ascii_alphanumeric() || byte == b'_') {
                break;
            }
            c = self.next_char();
        }
        self.backup(c);

        self.token(NAME)
    }

    fn number(&mut self, first: u8) -> Token {
        if first != b'0' {
            let mut c = self.next_char();
            while c.is_some_and(|byte| byte.is_ascii_digit()) {
                c = self.next_char();
            }
            if matches!(c, Some(b'l' | b'L')) {
                c = self.next_char();
                return self.end_number(c);
            }
            return self.number_after_integer(c);
        }

        let mut c = self.next_char();
        match c {
            Some(b'.') => return self.number_fraction(),
            Some(b'j' | b'J') => return self.number_imaginary(),
            Some(b'x' | b'X') => {
                c = self.next_char();
                if !c.is_some_and(|byte| byte.is_ascii_hexdigit()) {
                    return self.bad_token(c);
                }
                while c.is_some_and(|byte| byte.is_ascii_hexdigit()) {
                    c = self.next_char();
                }
            }
            Some(b'o' | b'O') => {
                c = self.next_char();
                if !matches!(c, Some(b'0'..=b'7')) {
                    return self.bad_token(c);
                }
                while matches!(c, Some(b'0'..=b'7')) {
                    c = self.next_char();
                }
            }
            Some(b'b' | b'B') => {
                c = self.next_char();
                if !matches!(c, Some(b'0' | b'1')) {
                    return self.bad_token(c);
                }
                while matches!(c, Some(b'0' | b'1')) {
                    c = self.next_char();
                }
            }
            _ => {
                let mut found_decimal = false;
                while matches!(c, Some(b'0'..=b'7')) {
                    c = self.next_char();
                }
                if c.is_some_and(|byte| byte.is_ascii_digit()) {
                    found_decimal = true;
                    while c.is_some_and(|byte| byte.is_ascii_digit()) {
                        c = self.next_char();
                    }
                }
                match c {
                    Some(b'.') => return self.number_fraction(),
                    Some(b'e' | b'E') => return self.number_exponent(c),
                    Some(b'j' | b'J') => return self.number_imaginary(),
                    _ if found_decimal => return self.bad_token(c),
                    _ => {}
                }
            }
        }

        if matches!(c, Some(b'l' | b'L')) {
            c = self.next_char();
        }

        self.end_number(c)
    }

    /// The `fraction:` label: a '.' was consumed.
    fn number_fraction(&mut self) -> Token {
        let mut c = self.next_char();
        while c.is_some_and(|byte| byte.is_ascii_digit()) {
            c = self.next_char();
        }

        self.number_after_integer_or_fraction(c)
    }

    fn number_after_integer(&mut self, c: Option<u8>) -> Token {
        if c == Some(b'.') {
            return self.number_fraction();
        }

        self.number_after_integer_or_fraction(c)
    }

    fn number_after_integer_or_fraction(&mut self, c: Option<u8>) -> Token {
        if matches!(c, Some(b'e' | b'E')) {
            return self.number_exponent(c);
        }

        self.number_suffix(c)
    }

    /// The `exponent:` label: `e` is the 'e' or 'E' just consumed.
    fn number_exponent(&mut self, e: Option<u8>) -> Token {
        let mut c = self.next_char();
        if matches!(c, Some(b'+' | b'-')) {
            c = self.next_char();
            if !c.is_some_and(|byte| byte.is_ascii_digit()) {
                return self.bad_token(c);
            }
        } else if !c.is_some_and(|byte| byte.is_ascii_digit()) {
            self.backup(c);
            self.backup(e);
            return self.token(NUMBER);
        }

        while c.is_some_and(|byte| byte.is_ascii_digit()) {
            c = self.next_char();
        }

        self.number_suffix(c)
    }

    fn number_suffix(&mut self, c: Option<u8>) -> Token {
        if matches!(c, Some(b'j' | b'J')) {
            return self.number_imaginary();
        }

        self.end_number(c)
    }

    /// The `imaginary:` label: the 'j' was consumed.
    fn number_imaginary(&mut self) -> Token {
        let c = self.next_char();

        self.end_number(c)
    }

    fn end_number(&mut self, c: Option<u8>) -> Token {
        self.backup(c);

        self.token(NUMBER)
    }

    fn bad_token(&mut self, c: Option<u8>) -> Token {
        self.done = Status::BadToken;
        self.backup(c);

        Token { kind: ERRORTOKEN, span: None }
    }

    /// A string literal, after its opening `quote` was consumed.
    fn string(&mut self, quote: u8) -> Token {
        let start = self.start.unwrap_or(self.cur);
        let quote2 = self.cur - start + 1;
        let mut triple = false;
        let mut tripcount = 0;

        loop {
            let c = self.next_char();
            match c {
                Some(b'\n') => {
                    if !triple {
                        self.done = Status::EolInString;
                        self.backup(c);
                        return Token { kind: ERRORTOKEN, span: None };
                    }
                    tripcount = 0;
                    self.cont_line = true;
                }
                None => {
                    let status = if triple { Status::EofInTripleQuoted } else { Status::EolInString };
                    return self.error(status);
                }
                Some(byte) if byte == quote => {
                    tripcount += 1;
                    if self.cur - start == quote2 {
                        let next = self.next_char();
                        if next == Some(quote) {
                            triple = true;
                            tripcount = 0;
                            continue;
                        }
                        self.backup(next);
                    }
                    if !triple || tripcount == 3 {
                        break;
                    }
                }
                Some(b'\\') => {
                    tripcount = 0;
                    if self.next_char().is_none() {
                        return self.error(Status::EolInString);
                    }
                }
                Some(_) => tripcount = 0,
            }
        }

        self.token(STRING)
    }

    fn operator(&mut self, c: u8) -> Token {
        let c2 = self.next_char();
        let kind = c2.map_or(OP, |second| two_chars(c, second));
        if kind != OP {
            let c3 = self.next_char();
            let kind3 = match (c2, c3) {
                (Some(second), Some(third)) => three_chars(c, second, third),
                _ => OP,
            };
            if kind3 != OP {
                return self.token(kind3);
            }
            self.backup(c3);
            return self.token(kind);
        }
        self.backup(c2);

        match c {
            b'(' | b'[' | b'{' => self.level += 1,
            b')' | b']' | b'}' => self.level -= 1,
            _ => {}
        }

        self.token(one_char(c))
    }
}

/// The token type of a one-character operator, or `OP`.
fn one_char(c: u8) -> u16 {
    match c {
        b'(' => LPAR,
        b')' => RPAR,
        b'[' => LSQB,
        b']' => RSQB,
        b':' => COLON,
        b',' => COMMA,
        b';' => SEMI,
        b'+' => PLUS,
        b'-' => MINUS,
        b'*' => STAR,
        b'/' => SLASH,
        b'|' => VBAR,
        b'&' => AMPER,
        b'<' => LESS,
        b'>' => GREATER,
        b'=' => EQUAL,
        b'.' => DOT,
        b'%' => PERCENT,
        b'`' => BACKQUOTE,
        b'{' => LBRACE,
        b'}' => RBRACE,
        b'^' => CIRCUMFLEX,
        b'~' => TILDE,
        b'@' => AT,
        _ => OP,
    }
}

/// The token type of a two-character operator, or `OP`.
fn two_chars(c1: u8, c2: u8) -> u16 {
    match (c1, c2) {
        (b'=', b'=') => EQEQUAL,
        (b'!', b'=') => NOTEQUAL,
        (b'<', b'>') => NOTEQUAL,
        (b'<', b'=') => LESSEQUAL,
        (b'<', b'<') => LEFTSHIFT,
        (b'>', b'=') => GREATEREQUAL,
        (b'>', b'>') => RIGHTSHIFT,
        (b'+', b'=') => PLUSEQUAL,
        (b'-', b'=') => MINEQUAL,
        (b'*', b'*') => DOUBLESTAR,
        (b'*', b'=') => STAREQUAL,
        (b'/', b'/') => DOUBLESLASH,
        (b'/', b'=') => SLASHEQUAL,
        (b'|', b'=') => VBAREQUAL,
        (b'%', b'=') => PERCENTEQUAL,
        (b'&', b'=') => AMPEREQUAL,
        (b'^', b'=') => CIRCUMFLEXEQUAL,
        _ => OP,
    }
}

/// The token type of a three-character operator, or `OP`.
fn three_chars(c1: u8, c2: u8, c3: u8) -> u16 {
    match (c1, c2, c3) {
        (b'<', b'<', b'=') => LEFTSHIFTEQUAL,
        (b'>', b'>', b'=') => RIGHTSHIFTEQUAL,
        (b'*', b'*', b'=') => DOUBLESTAREQUAL,
        (b'/', b'/', b'=') => DOUBLESLASHEQUAL,
        _ => OP,
    }
}

/// C `atoi` on the text after a tab-size setting.
fn c_atoi(text: &[u8]) -> i64 {
    let mut position = 0;
    while text.get(position).is_some_and(|&byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')) {
        position += 1;
    }

    let negative = match text.get(position) {
        Some(b'-') => {
            position += 1;
            true
        }
        Some(b'+') => {
            position += 1;
            false
        }
        _ => false,
    };

    let mut value: i64 = 0;
    while let Some(&digit @ b'0'..=b'9') = text.get(position) {
        value = value.saturating_mul(10).saturating_add(i64::from(digit - b'0'));
        position += 1;
    }

    if negative { -value } else { value }
}

/// `translate_newlines`: `\r\n` and `\r` become `\n`, and exec input gains
/// a final newline when it lacks one. The input ends at its first NUL, as a
/// C string does.
pub fn translate_newlines(input: &[u8], exec_input: bool) -> Vec<u8> {
    let input = match input.iter().position(|&byte| byte == 0) {
        Some(nul) => &input[..nul],
        None => input,
    };

    let mut output = Vec::with_capacity(input.len() + 1);
    let mut skip_next_lf = false;
    let mut last = 0u8;
    let mut position = 0;
    while position < input.len() {
        let mut c = input[position];
        if skip_next_lf {
            skip_next_lf = false;
            if c == b'\n' {
                position += 1;
                match input.get(position) {
                    Some(&next) => c = next,
                    None => {
                        // C leaves `c` holding the terminating NUL here.
                        last = 0;
                        break;
                    }
                }
            }
        }
        if c == b'\r' {
            skip_next_lf = true;
            c = b'\n';
        }
        output.push(c);
        last = c;
        position += 1;
    }

    if exec_input && last != b'\n' {
        output.push(b'\n');
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &[u8]) -> Vec<u16> {
        let text = translate_newlines(source, true);
        let mut tokenizer = Tokenizer::new(&text);
        let mut kinds = Vec::new();
        loop {
            let token = tokenizer.next_token();
            kinds.push(token.kind);
            if token.kind == ENDMARKER || token.kind == ERRORTOKEN {
                return kinds;
            }
        }
    }

    #[test]
    fn newlines_are_translated() {
        assert_eq!(translate_newlines(b"a\r\nb\rc", true), b"a\nb\nc\n");
        assert_eq!(translate_newlines(b"a\r\n", true), b"a\n\n");
        assert_eq!(translate_newlines(b"", true), b"\n");
        assert_eq!(translate_newlines(b"x", false), b"x");
    }

    #[test]
    fn indentation_produces_indent_and_dedent() {
        assert_eq!(kinds(b"if x:\n\ty\nz\n"), vec![NAME, NAME, COLON, NEWLINE, INDENT, NAME, NEWLINE, DEDENT, NAME, NEWLINE, ENDMARKER]);
    }

    #[test]
    fn exponent_without_digits_splits_number() {
        assert_eq!(kinds(b"1e\n"), vec![NUMBER, NAME, NEWLINE, ENDMARKER]);
        assert_eq!(kinds(b"1if 1else 2\n"), vec![NUMBER, NAME, NUMBER, NAME, NUMBER, NEWLINE, ENDMARKER]);
    }
}
