//! Validation of the trees `parser.sequence2st` builds from nested
//! sequences, with the acceptance rules and `ParserError` messages of the
//! CPython 2.7 `parser` module.
//!
//! The rules are those the module applies, not the grammar's: it accepts
//! some trees the parser never produces, rejects some it does, and in a
//! few places records a message for a failed check whose failure it then
//! ignores. Where the module would read a child past the end of a node or
//! the text of a nonterminal, the outcome is [`Undefined`].

use crate::interp::compiler::parser::Cst;
use crate::interp::compiler::parser::CstNode;
use crate::interp::compiler::symbol;
use crate::interp::compiler::tokenizer;

/// A read of a child that does not exist or of the text of a nonterminal.
pub struct Undefined;

type Outcome = Result<bool, Undefined>;

type Rule<'a> = fn(&mut Validator<'a>, u32) -> Outcome;

/// A validator over one tree and the `ParserError` message it has set.
pub struct Validator<'a> {
    nodes: &'a [CstNode],
    text: &'a [u8],
    error: Option<Vec<u8>>,
}

impl<'a> Validator<'a> {
    pub fn new(cst: &'a Cst) -> Self {
        Self {
            nodes: &cst.nodes,
            text: &cst.text,
            error: None,
        }
    }

    /// The message of the last failed check that set one.
    pub fn into_error(self) -> Option<Vec<u8>> {
        self.error
    }

    /// An `eval_input` root.
    pub fn expr_tree(&mut self, root: u32) -> Outcome {
        let valid = self.eval_input(root)?;
        self.fallback(valid, "could not validate expression tuple");

        Ok(valid)
    }

    /// A `file_input` root; the type of the root itself is not checked.
    pub fn file_input_tree(&mut self, root: u32) -> Outcome {
        let valid = self.file_input(root)?;
        self.fallback(valid, "VALIDATION FAILURE: report this to the maintainer!");

        Ok(valid)
    }

    /// An `encoding_decl` root, whose one child is a `file_input`.
    pub fn encoding_decl(&mut self, root: u32) -> Outcome {
        let valid = self.count(root) == 1 && self.file_input_tree(self.child(root, 0)?)?;
        self.fallback(valid, "Error Parsing encoding_decl");

        Ok(valid)
    }
}

/// Node access and the checks the rules share.
impl<'a> Validator<'a> {
    /// The node type as the C `short` it is stored in.
    fn kind(&self, node: u32) -> i32 {
        i32::from(self.nodes[node as usize].kind as i16)
    }

    fn is(&self, node: u32, kind: u16) -> bool {
        self.kind(node) == i32::from(kind)
    }

    fn count(&self, node: u32) -> usize {
        self.nodes[node as usize].children.len()
    }

    fn child(&self, node: u32, index: usize) -> Result<u32, Undefined> {
        self.nodes[node as usize]
            .children
            .get(index)
            .copied()
            .ok_or(Undefined)
    }

    /// The token text of a terminal.
    fn text(&self, node: u32) -> Result<&'a [u8], Undefined> {
        if self.kind(node) >= i32::from(tokenizer::NT_OFFSET) {
            return Err(Undefined);
        }
        let data = &self.nodes[node as usize];

        Ok(&self.text[data.start..data.end])
    }

    /// Whether `node` is a `NAME` whose text is `word`.
    fn is_word(&self, node: u32, word: &str) -> bool {
        let data = &self.nodes[node as usize];

        self.is(node, tokenizer::NAME) && &self.text[data.start..data.end] == word.as_bytes()
    }

    fn fail(&mut self, message: &str) -> bool {
        self.fail_bytes(message.as_bytes().to_vec())
    }

    /// A message holding token text, which need not be UTF-8.
    fn fail_bytes(&mut self, message: Vec<u8>) -> bool {
        self.error = Some(message);

        false
    }

    /// Sets `message` when a failed check left none.
    fn fallback(&mut self, valid: bool, message: &str) {
        if !valid && self.error.is_none() {
            self.fail(message);
        }
    }

    fn expect_kind(&mut self, node: u32, kind: u16) -> bool {
        let actual = self.kind(node);
        if actual == i32::from(kind) {
            return true;
        }

        self.fail(&format!("Expected node type {kind}, got {actual}."))
    }

    fn expect_count(&mut self, valid: bool, name: &str) -> bool {
        valid || self.fail(&format!("Illegal number of children for {name} node."))
    }

    /// A node of `kind` whose count is allowed. On failure, a count other
    /// than `usual` is reported over any wrong type.
    fn shape(&mut self, node: u32, kind: u16, allowed: bool, usual: usize, name: &str) -> bool {
        if self.expect_kind(node, kind) && allowed {
            return true;
        }
        self.expect_count(self.count(node) == usual, name);

        false
    }

    /// A terminal of `kind` whose text is `expected`. A wrong text is
    /// reported only when no message is set, as in 2.7.12; later releases
    /// replace a message already set.
    fn terminal(&mut self, node: u32, kind: u16, expected: &str) -> bool {
        if !self.expect_kind(node, kind) {
            return false;
        }
        let data = &self.nodes[node as usize];
        if &self.text[data.start..data.end] == expected.as_bytes() {
            return true;
        }
        self.fallback(false, &format!("Illegal terminal: expected \"{expected}\""));

        false
    }

    fn keyword(&mut self, node: u32, word: &str) -> bool {
        self.terminal(node, tokenizer::NAME, word)
    }

    fn name(&mut self, node: u32) -> bool {
        self.expect_kind(node, tokenizer::NAME)
    }

    fn colon(&mut self, node: u32) -> bool {
        self.terminal(node, tokenizer::COLON, ":")
    }

    fn comma(&mut self, node: u32) -> bool {
        self.terminal(node, tokenizer::COMMA, ",")
    }

    /// A rule applied through a growing stack, as trees nest as deep as
    /// the parser allows.
    fn apply(&mut self, rule: Rule<'a>, node: u32) -> Outcome {
        stacker::maybe_grow(64 * 1024, 2 * 1024 * 1024, || rule(self, node))
    }

    /// Comma-separated elements, with an optional trailing comma, under a
    /// node of `kind`.
    ///
    /// A failure of the first element without a message reports the
    /// count instead. Any other failure of the first element is set aside
    /// when the count is even: the trailing comma and the later elements
    /// decide.
    fn list(&mut self, node: u32, kind: u16, name: &str, element: Rule<'a>) -> Outcome {
        let count = self.count(node);
        let mut valid = count > 0
            && self.expect_kind(node, kind)
            && self.apply(element, self.child(node, 0)?)?;
        if !valid && self.error.is_none() {
            if count != 1 {
                self.expect_count(false, name);
            }
            return Ok(false);
        }

        // With an error already set, an empty node reads the child before
        // its first.
        let mut end = count;
        if count % 2 == 0 {
            let Some(last) = count.checked_sub(1) else {
                return Err(Undefined);
            };
            end = last;
            valid = self.comma(self.child(node, end)?);
        }
        let mut index = 1;
        while valid && index < end {
            valid = self.comma(self.child(node, index)?)
                && self.apply(element, self.child(node, index + 1)?)?;
            index += 2;
        }

        Ok(valid)
    }

    /// Operands joined by operators, checking each operator before the
    /// operand that follows it.
    fn chain(
        &mut self,
        node: u32,
        operand: Rule<'a>,
        operator: fn(&mut Self, u32) -> bool,
    ) -> Outcome {
        let count = self.count(node);
        if count % 2 == 0 || !self.apply(operand, self.child(node, 0)?)? {
            return Ok(false);
        }
        for index in (1..count).step_by(2) {
            if !operator(self, self.child(node, index)?)
                || !self.apply(operand, self.child(node, index + 1)?)?
            {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// Module structure and simple statements.
impl<'a> Validator<'a> {
    fn file_input(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if count == 0 || !self.expect_kind(self.child(node, count - 1)?, tokenizer::ENDMARKER) {
            return Ok(false);
        }
        for index in 0..count - 1 {
            let child = self.child(node, index)?;
            let valid = if self.is(child, symbol::STMT) {
                self.apply(Self::stmt, child)?
            } else {
                self.expect_kind(child, tokenizer::NEWLINE)
            };
            if !valid {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn eval_input(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if count < 2 || !self.testlist(self.child(node, 0)?)? {
            return Ok(false);
        }
        if !self.expect_kind(self.child(node, count - 1)?, tokenizer::ENDMARKER) {
            return Ok(false);
        }
        for index in 1..count - 1 {
            if !self.expect_kind(self.child(node, index)?, tokenizer::NEWLINE) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn stmt(&mut self, node: u32) -> Outcome {
        if !self.expect_count(self.count(node) == 1, "stmt") {
            return Ok(false);
        }
        let child = self.child(node, 0)?;

        if self.is(child, symbol::SIMPLE_STMT) {
            self.simple_stmt(child)
        } else {
            self.compound_stmt(child)
        }
    }

    fn simple_stmt(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !self.shape(node, symbol::SIMPLE_STMT, count >= 2, 2, "simple_stmt")
            || !self.small_stmt(self.child(node, 0)?)?
        {
            return Ok(false);
        }
        if !self.expect_kind(self.child(node, count - 1)?, tokenizer::NEWLINE) {
            return Ok(false);
        }

        let mut end = count - 1;
        if end % 2 == 0 {
            if !self.semicolon(self.child(node, end - 1)?) {
                return Ok(false);
            }
            end -= 1;
        }
        for index in (1..end).step_by(2) {
            if !self.semicolon(self.child(node, index)?)
                || !self.small_stmt(self.child(node, index + 1)?)?
            {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn semicolon(&mut self, node: u32) -> bool {
        self.terminal(node, tokenizer::SEMI, ";")
    }

    fn small_stmt(&mut self, node: u32) -> Outcome {
        if !self.expect_count(self.count(node) == 1, "small_stmt") {
            return Ok(false);
        }
        let child = self.child(node, 0)?;
        let rule: Rule<'a> = match self.kind(child) {
            kind if kind == i32::from(symbol::EXPR_STMT) => Self::expr_stmt,
            kind if kind == i32::from(symbol::PRINT_STMT) => Self::print_stmt,
            kind if kind == i32::from(symbol::DEL_STMT) => Self::del_stmt,
            kind if kind == i32::from(symbol::PASS_STMT) => Self::pass_stmt,
            kind if kind == i32::from(symbol::FLOW_STMT) => Self::flow_stmt,
            kind if kind == i32::from(symbol::IMPORT_STMT) => Self::import_stmt,
            kind if kind == i32::from(symbol::GLOBAL_STMT) => Self::global_stmt,
            kind if kind == i32::from(symbol::EXEC_STMT) => Self::exec_stmt,
            kind if kind == i32::from(symbol::ASSERT_STMT) => Self::assert_stmt,
            _ => return Ok(self.fail("illegal small_stmt child type")),
        };

        self.apply(rule, child)
    }

    fn expr_stmt(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if count % 2 == 0 || !self.testlist(self.child(node, 0)?)? {
            return Ok(false);
        }
        if count == 3 && self.is(self.child(node, 1)?, symbol::AUGASSIGN) {
            let operator = self.child(node, 1)?;
            if !self.expect_count(self.count(operator) == 1, "augassign")
                || !self.assigned(self.child(node, 2)?)?
            {
                return Ok(false);
            }
            return self.augassign(operator);
        }
        for index in (1..count).step_by(2) {
            if !self.terminal(self.child(node, index)?, tokenizer::EQUAL, "=")
                || !self.assigned(self.child(node, index + 1)?)?
            {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// The right side of an assignment: `yield_expr | testlist`.
    fn assigned(&mut self, node: u32) -> Outcome {
        if self.is(node, symbol::YIELD_EXPR) {
            self.yield_expr(node)
        } else {
            self.testlist(node)
        }
    }

    /// The text of an augmented assignment operator.
    fn augassign(&mut self, node: u32) -> Outcome {
        const OPERATORS: [&[u8]; 12] = [
            b"+=", b"-=", b"*=", b"/=", b"%=", b"&=", b"|=", b"^=", b"<<=", b">>=", b"**=", b"//=",
        ];

        if OPERATORS.contains(&self.text(self.child(node, 0)?)?) {
            return Ok(true);
        }

        Ok(self.fail("illegal augmented assignment operator"))
    }

    fn print_stmt(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if count == 0 || !self.keyword(self.child(node, 0)?, "print") {
            return Ok(false);
        }
        if count == 1 {
            return Ok(true);
        }
        if self.is(self.child(node, 1)?, symbol::TEST) {
            return self.test_tail(node, 1);
        }
        if !self.expect_count(count >= 3, "print_stmt")
            || !self.expect_kind(self.child(node, 1)?, tokenizer::RIGHTSHIFT)
            || !self.test(self.child(node, 2)?)?
        {
            return Ok(false);
        }
        if count == 3 {
            return Ok(true);
        }
        if !self.expect_count(count >= 5, "print_stmt") {
            return Ok(false);
        }

        self.comma_tail(node, 3)
    }

    /// Children from `start` as comma-separated tests with an optional
    /// trailing comma.
    fn test_tail(&mut self, node: u32, start: usize) -> Outcome {
        if !self.test(self.child(node, start)?)? {
            return Ok(false);
        }

        self.comma_tail(node, start + 1)
    }

    /// Children from `start` as further tests, each after a comma, with an
    /// optional trailing comma.
    fn comma_tail(&mut self, node: u32, start: usize) -> Outcome {
        let count = self.count(node);
        let mut index = start;
        while index < count {
            if !self.comma(self.child(node, index)?) {
                return Ok(false);
            }
            if index + 1 < count && !self.test(self.child(node, index + 1)?)? {
                return Ok(false);
            }
            index += 2;
        }

        Ok(true)
    }

    fn del_stmt(&mut self, node: u32) -> Outcome {
        Ok(self.expect_count(self.count(node) == 2, "del_stmt")
            && self.keyword(self.child(node, 0)?, "del")
            && self.exprlist(self.child(node, 1)?)?)
    }

    fn pass_stmt(&mut self, node: u32) -> Outcome {
        Ok(self.expect_count(self.count(node) == 1, "pass")
            && self.keyword(self.child(node, 0)?, "pass"))
    }

    fn flow_stmt(&mut self, node: u32) -> Outcome {
        if !self.expect_count(self.count(node) == 1, "flow_stmt") {
            return Ok(false);
        }
        let child = self.child(node, 0)?;
        let rule: Rule<'a> = match self.kind(child) {
            kind if kind == i32::from(symbol::BREAK_STMT) => Self::break_stmt,
            kind if kind == i32::from(symbol::CONTINUE_STMT) => Self::continue_stmt,
            kind if kind == i32::from(symbol::RETURN_STMT) => Self::return_stmt,
            kind if kind == i32::from(symbol::RAISE_STMT) => Self::raise_stmt,
            kind if kind == i32::from(symbol::YIELD_STMT) => Self::yield_stmt,
            _ => return Ok(self.fail("illegal flow_stmt type")),
        };

        self.apply(rule, child)
    }

    fn break_stmt(&mut self, node: u32) -> Outcome {
        Ok(self.expect_count(self.count(node) == 1, "break")
            && self.keyword(self.child(node, 0)?, "break"))
    }

    fn continue_stmt(&mut self, node: u32) -> Outcome {
        Ok(self.expect_count(self.count(node) == 1, "continue")
            && self.keyword(self.child(node, 0)?, "continue"))
    }

    fn return_stmt(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !(count == 1 || count == 2) || !self.keyword(self.child(node, 0)?, "return") {
            return Ok(false);
        }

        Ok(count == 1 || self.testlist(self.child(node, 1)?)?)
    }

    fn yield_stmt(&mut self, node: u32) -> Outcome {
        Ok(self.expect_count(self.count(node) == 1, "yield_stmt")
            && self.yield_expr(self.child(node, 0)?)?)
    }

    fn raise_stmt(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !self.expect_count(matches!(count, 1 | 2 | 4 | 6), "raise")
            || !self.keyword(self.child(node, 0)?, "raise")
        {
            return Ok(false);
        }
        if count >= 2 && !self.test(self.child(node, 1)?)? {
            return Ok(false);
        }
        for index in (2..count).step_by(2) {
            if !self.comma(self.child(node, index)?) || !self.test(self.child(node, index + 1)?)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn import_stmt(&mut self, node: u32) -> Outcome {
        if !self.expect_count(self.count(node) == 1, "import_stmt") {
            return Ok(false);
        }
        let child = self.child(node, 0)?;
        if self.is(child, symbol::IMPORT_NAME) {
            return self.import_name(child);
        }
        if self.is(child, symbol::IMPORT_FROM) {
            return self.import_from(child);
        }

        Ok(self.fail("illegal import_stmt child type"))
    }

    fn import_name(&mut self, node: u32) -> Outcome {
        Ok(self.expect_count(self.count(node) == 2, "import_name")
            && self.keyword(self.child(node, 0)?, "import")
            && self.dotted_as_names(self.child(node, 1)?)?)
    }

    /// A `from` import: leading dots and an optional module name, the
    /// keyword `import`, then a star, a parenthesized name list, or a bare
    /// name list.
    ///
    /// The dots, the module name, and the form of the imported names are
    /// found by type alone, and children after the names are not checked.
    fn import_from(&mut self, node: u32) -> Outcome {
        let count = self.count(node);

        // The dots are scanned before the count is checked, and a run of
        // dots that reaches the end reads one child past it.
        let mut module = 1;
        while self.is(self.child(node, module)?, tokenizer::DOT) {
            module += 1;
        }
        let named = self.is(self.child(node, module)?, symbol::DOTTED_NAME);
        let import = if named { module + 1 } else { module };
        if count < 4 || (module == 1 && !named) || import + 2 > count {
            return Ok(false);
        }
        if !self.keyword(self.child(node, 0)?, "from") {
            return Ok(false);
        }
        if named && !self.dotted_name(self.child(node, module)?)? {
            return Ok(false);
        }
        if !self.keyword(self.child(node, import)?, "import") {
            return Ok(false);
        }

        let target = self.child(node, import + 1)?;
        if self.is(target, tokenizer::LPAR) {
            return Ok(count == import + 4
                && self.terminal(target, tokenizer::LPAR, "(")
                && self.import_as_names(self.child(node, import + 2)?)?
                && self.terminal(self.child(node, import + 3)?, tokenizer::RPAR, ")"));
        }
        if self.is(target, tokenizer::STAR) {
            return Ok(true);
        }

        self.import_as_names(target)
    }

    fn import_as_name(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !self.expect_count(count == 1 || count == 3, "import_as_name")
            || !self.name(self.child(node, 0)?)
        {
            return Ok(false);
        }

        Ok(count == 1
            || (self.keyword(self.child(node, 1)?, "as") && self.name(self.child(node, 2)?)))
    }

    fn dotted_as_name(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !(count == 1 || count == 3) {
            return Ok(self.fail("illegal number of children for dotted_as_name"));
        }
        if !self.dotted_name(self.child(node, 0)?)? {
            return Ok(false);
        }

        Ok(count == 1
            || (self.keyword(self.child(node, 1)?, "as") && self.name(self.child(node, 2)?)))
    }

    /// Comma-separated imported names with an optional trailing comma; a
    /// node of two
    /// children has its second left unchecked.
    fn import_as_names(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        let first = self.child(node, 0)?;
        if !self.expect_kind(first, symbol::IMPORT_AS_NAME) || !self.import_as_name(first)? {
            return Ok(false);
        }
        let mut index = 1;
        while index + 1 < count {
            let element = self.child(node, index + 1)?;
            if !self.comma(self.child(node, index)?)
                || !self.expect_kind(element, symbol::IMPORT_AS_NAME)
                || !self.import_as_name(element)?
            {
                return Ok(false);
            }
            index += 2;
        }

        Ok(true)
    }

    fn dotted_as_names(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if count % 2 == 0 {
            return Ok(false);
        }
        for index in (0..count).step_by(2) {
            let element = self.child(node, index)?;
            if index > 0 && !self.comma(self.child(node, index - 1)?) {
                return Ok(false);
            }
            if !self.expect_kind(element, symbol::DOTTED_AS_NAME)
                || !self.dotted_as_name(element)?
            {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn dotted_name(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !self.expect_kind(node, symbol::DOTTED_NAME)
            || count % 2 == 0
            || !self.name(self.child(node, 0)?)
        {
            return Ok(false);
        }
        for index in (1..count).step_by(2) {
            if !self.terminal(self.child(node, index)?, tokenizer::DOT, ".")
                || !self.name(self.child(node, index + 1)?)
            {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn global_stmt(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if count < 2 || count % 2 != 0 {
            self.fallback(false, "illegal global statement");
            return Ok(false);
        }
        if !self.keyword(self.child(node, 0)?, "global") || !self.name(self.child(node, 1)?) {
            return Ok(false);
        }
        for index in (2..count).step_by(2) {
            if !self.comma(self.child(node, index)?) || !self.name(self.child(node, index + 1)?) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// The fallback message covers the count, the keyword, and the code.
    fn exec_stmt(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        let valid = matches!(count, 2 | 4 | 6)
            && self.keyword(self.child(node, 0)?, "exec")
            && self.expr(self.child(node, 1)?)?;
        self.fallback(valid, "illegal exec statement");
        if !valid {
            return Ok(false);
        }
        if count >= 4
            && !(self.keyword(self.child(node, 2)?, "in") && self.test(self.child(node, 3)?)?)
        {
            return Ok(false);
        }

        Ok(count < 6 || (self.comma(self.child(node, 4)?) && self.test(self.child(node, 5)?)?))
    }

    /// The fallback message covers the count, the keyword, and the test.
    fn assert_stmt(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        let valid = matches!(count, 2 | 4)
            && self.keyword(self.child(node, 0)?, "assert")
            && self.test(self.child(node, 1)?)?;
        self.fallback(valid, "illegal assert statement");
        if !valid {
            return Ok(false);
        }

        Ok(count < 4 || (self.comma(self.child(node, 2)?) && self.test(self.child(node, 3)?)?))
    }
}

/// Compound statements and definitions.
impl<'a> Validator<'a> {
    fn compound_stmt(&mut self, node: u32) -> Outcome {
        if !self.expect_kind(node, symbol::COMPOUND_STMT)
            || !self.expect_count(self.count(node) == 1, "compound_stmt")
        {
            return Ok(false);
        }
        let child = self.child(node, 0)?;
        let rule: Rule<'a> = match self.kind(child) {
            kind if kind == i32::from(symbol::IF_STMT) => Self::if_stmt,
            kind if kind == i32::from(symbol::WHILE_STMT) => Self::while_stmt,
            kind if kind == i32::from(symbol::FOR_STMT) => Self::for_stmt,
            kind if kind == i32::from(symbol::TRY_STMT) => Self::try_stmt,
            kind if kind == i32::from(symbol::WITH_STMT) => Self::with_stmt,
            kind if kind == i32::from(symbol::FUNCDEF) => Self::funcdef,
            kind if kind == i32::from(symbol::CLASSDEF) => Self::classdef,
            kind if kind == i32::from(symbol::DECORATED) => Self::decorated,
            kind => return Ok(self.fail(&format!("Illegal compound statement type: {kind}."))),
        };

        self.apply(rule, child)
    }

    /// A keyword, condition, colon, and block at children
    /// `start..start + 4`.
    fn conditional_suite(&mut self, node: u32, start: usize, word: &str) -> Outcome {
        Ok(self.keyword(self.child(node, start)?, word)
            && self.test(self.child(node, start + 1)?)?
            && self.colon(self.child(node, start + 2)?)
            && self.suite(self.child(node, start + 3)?)?)
    }

    /// An `elif` clause at children `start..start + 4`, checking the
    /// colon before the condition.
    fn elif_suite(&mut self, node: u32, start: usize) -> Outcome {
        Ok(self.keyword(self.child(node, start)?, "elif")
            && self.colon(self.child(node, start + 2)?)
            && self.test(self.child(node, start + 1)?)?
            && self.suite(self.child(node, start + 3)?)?)
    }

    /// A keyword, colon, and block at children `start..start + 3`.
    fn keyword_suite(&mut self, node: u32, start: usize, word: &str) -> Outcome {
        Ok(self.keyword(self.child(node, start)?, word)
            && self.colon(self.child(node, start + 1)?)
            && self.suite(self.child(node, start + 2)?)?)
    }

    /// The `if` clause first, then an `else` clause when the count allows
    /// one. A silent failure of the `if` clause is reported as a count
    /// unless the node has four children, and a count left over after a
    /// failed `if` clause replaces any message.
    fn if_stmt(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        let head = count >= 4 && self.conditional_suite(node, 0, "if")?;
        let mut valid = head;
        let mut end = count;
        if head && count % 4 == 3 {
            valid = self.keyword_suite(node, count - 3, "else")?;
            end -= 3;
        } else if !head && self.error.is_none() {
            self.expect_count(count == 4, "if");
        }
        if end % 4 != 0 {
            return Ok(self.expect_count(false, "if"));
        }
        for start in (4..end).step_by(4) {
            if !valid {
                break;
            }
            valid = self.elif_suite(node, start)?;
        }

        Ok(valid)
    }

    fn while_stmt(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !(count == 4 || count == 7) || !self.conditional_suite(node, 0, "while")? {
            return Ok(false);
        }

        Ok(count == 4 || self.keyword_suite(node, 4, "else")?)
    }

    fn for_stmt(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !(count == 6 || count == 9) || !self.keyword(self.child(node, 0)?, "for") {
            return Ok(false);
        }
        let valid = self.exprlist(self.child(node, 1)?)?
            && self.keyword(self.child(node, 2)?, "in")
            && self.testlist(self.child(node, 3)?)?
            && self.colon(self.child(node, 4)?)
            && self.suite(self.child(node, 5)?)?;

        Ok(valid && (count == 6 || self.keyword_suite(node, 6, "else")?))
    }

    /// The `try` clause and the colon and suite of the last clause are
    /// checked first, then the other clauses in order.
    fn try_stmt(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if count < 6 || count % 3 != 0 {
            // The message names the clause three children from the end,
            // which is read only when no message is set.
            if self.error.is_some() {
                return Ok(false);
            }
            let Some(index) = count.checked_sub(3) else {
                return Err(Undefined);
            };
            let clause = self.child(node, index)?;
            let label = if self.is(clause, symbol::EXCEPT_CLAUSE) {
                b"except".as_slice()
            } else {
                self.text(clause)?
            };
            let message = [
                b"Illegal number of children for try/".as_slice(),
                label,
                b" node.".as_slice(),
            ]
            .concat();
            return Ok(self.fail_bytes(message));
        }
        if !self.keyword_suite(node, 0, "try")?
            || !self.colon(self.child(node, count - 2)?)
            || !self.suite(self.child(node, count - 1)?)?
        {
            return Ok(false);
        }
        if self.is_word(self.child(node, 3)?, "finally") {
            return Ok(self.expect_count(count == 6, "try/finally"));
        }

        let mut index = 3;
        while index < count && self.is(self.child(node, index)?, symbol::EXCEPT_CLAUSE) {
            if !(self.except_clause(self.child(node, index)?)?
                && self.colon(self.child(node, index + 1)?)
                && self.suite(self.child(node, index + 2)?)?)
            {
                return Ok(false);
            }
            index += 3;
        }
        if index < count && self.is_word(self.child(node, index)?, "else") {
            if !self.keyword_suite(node, index, "else")? {
                return Ok(false);
            }
            index += 3;
        }
        if index < count {
            if !self.keyword_suite(node, index, "finally")? {
                return Ok(false);
            }
            index += 3;
        }

        Ok(self.expect_count(index == count, "try/except/finally"))
    }

    /// The separators between items are not checked.
    fn with_stmt(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if count % 2 != 0 || !self.keyword(self.child(node, 0)?, "with") {
            return Ok(false);
        }
        if !self.colon(self.child(node, count - 2)?) || !self.suite(self.child(node, count - 1)?)? {
            return Ok(false);
        }
        for index in (1..count - 2).step_by(2) {
            let item = self.child(node, index)?;
            if !self.expect_kind(item, symbol::WITH_ITEM) || !self.with_item(item)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn with_item(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !(count == 1 || count == 3) || !self.test(self.child(node, 0)?)? {
            return Ok(false);
        }

        Ok(count == 1
            || (self.keyword(self.child(node, 1)?, "as") && self.expr(self.child(node, 2)?)?))
    }

    fn except_clause(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !matches!(count, 1 | 2 | 4) || !self.keyword(self.child(node, 0)?, "except") {
            return Ok(false);
        }
        if count >= 2 && !self.test(self.child(node, 1)?)? {
            return Ok(false);
        }
        if count < 4 {
            return Ok(true);
        }
        let separator = self.child(node, 2)?;
        let valid = if self.is(separator, tokenizer::NAME) {
            self.keyword(separator, "as")
        } else {
            self.comma(separator)
        };

        Ok(valid && self.test(self.child(node, 3)?)?)
    }

    /// One line of statements, or a newline and an indented block of
    /// statements. The closing `DEDENT` is
    /// checked after the first statement and before the others.
    fn suite(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !self.expect_kind(node, symbol::SUITE) {
            return Ok(false);
        }
        if count == 1 {
            return self.simple_stmt(self.child(node, 0)?);
        }
        if count < 4
            || !self.expect_kind(self.child(node, 0)?, tokenizer::NEWLINE)
            || !self.expect_kind(self.child(node, 1)?, tokenizer::INDENT)
        {
            return Ok(false);
        }
        if !self.statement(self.child(node, 2)?)?
            || !self.terminal(self.child(node, count - 1)?, tokenizer::DEDENT, "")
        {
            return Ok(false);
        }
        for index in 3..count - 1 {
            if !self.statement(self.child(node, index)?)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// A `stmt` child of a block.
    fn statement(&mut self, node: u32) -> Outcome {
        Ok(self.expect_kind(node, symbol::STMT) && self.apply(Self::stmt, node)?)
    }

    fn funcdef(&mut self, node: u32) -> Outcome {
        Ok(self.count(node) == 5
            && self.keyword(self.child(node, 0)?, "def")
            && self.name(self.child(node, 1)?)
            && self.colon(self.child(node, 3)?)
            && self.parameters(self.child(node, 2)?)?
            && self.suite(self.child(node, 4)?)?)
    }

    fn parameters(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !self.shape(
            node,
            symbol::PARAMETERS,
            count == 2 || count == 3,
            2,
            "parameters",
        ) {
            return Ok(false);
        }
        if !self.terminal(self.child(node, 0)?, tokenizer::LPAR, "(")
            || !self.terminal(self.child(node, count - 1)?, tokenizer::RPAR, ")")
        {
            return Ok(false);
        }

        Ok(count == 2 || self.varargslist(self.child(node, 1)?)?)
    }

    /// Parameter lists: when the first child is an `fpdef`, the last child
    /// decides whether a `*`/`**` trailer ends the list.
    fn varargslist(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !self.expect_kind(node, symbol::VARARGSLIST) || count == 0 {
            return Ok(false);
        }
        let first = self.child(node, 0)?;
        if self.is(first, tokenizer::STAR) || self.is(first, tokenizer::DOUBLESTAR) {
            return self.varargs_trailer(node, 0);
        }
        if !self.is(first, symbol::FPDEF) {
            return Ok(true);
        }
        if self.is(self.child(node, count - 1)?, tokenizer::NAME) {
            return self.parameters_with_trailer(node);
        }

        let mut end = count;
        if self.is(self.child(node, count - 1)?, tokenizer::COMMA) {
            if !self.comma(self.child(node, count - 1)?) {
                return Ok(false);
            }
            end -= 1;
        }
        let mut index = 0;
        while index < end {
            if !self.fpdef(self.child(node, index)?)? {
                return Ok(false);
            }
            index += 1;
            if index + 1 < end && self.is(self.child(node, index)?, tokenizer::EQUAL) {
                if !self.default_value(node, index)? {
                    return Ok(false);
                }
                index += 2;
            }
            if index < end {
                if index == end - 1 {
                    return Ok(self.fail("illegal formation for varargslist"));
                }
                if !self.comma(self.child(node, index)?) {
                    return Ok(false);
                }
                index += 1;
            }
        }

        Ok(true)
    }

    /// Parameters ending in a `NAME`: groups of a parameter, an optional
    /// default, and a comma
    /// while more than one child remains and no `*` or `**` starts one,
    /// then the trailer.
    fn parameters_with_trailer(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        let mut index = 0;
        while index + 1 < count {
            let child = self.child(node, index)?;
            if self.is(child, tokenizer::STAR) || self.is(child, tokenizer::DOUBLESTAR) {
                break;
            }
            if !self.fpdef(child)? {
                return Ok(false);
            }
            index += 1;
            if self.is(self.child(node, index)?, tokenizer::EQUAL) {
                if !self.default_value(node, index)? {
                    return Ok(false);
                }
                index += 2;
            }
            if !self.comma(self.child(node, index)?) {
                return Ok(false);
            }
            index += 1;
        }

        self.varargs_trailer(node, index)
    }

    /// A default value after `=` at children `index..index + 2`.
    fn default_value(&mut self, node: u32, index: usize) -> Outcome {
        Ok(
            self.terminal(self.child(node, index)?, tokenizer::EQUAL, "=")
                && self.test(self.child(node, index + 1)?)?,
        )
    }

    /// Star and double-star parameter names from child `start` to the end.
    /// The leading star is found by type; any failure is reported as one
    /// message.
    fn varargs_trailer(&mut self, node: u32, start: usize) -> Outcome {
        let remaining = self.count(node) - start;
        let first = self.child(node, start)?;
        let valid = if self.is(first, tokenizer::STAR) {
            match remaining {
                2 => self.name(self.child(node, start + 1)?),
                5 => {
                    self.name(self.child(node, start + 1)?)
                        && self.comma(self.child(node, start + 2)?)
                        && self.terminal(self.child(node, start + 3)?, tokenizer::DOUBLESTAR, "**")
                        && self.name(self.child(node, start + 4)?)
                }
                _ => false,
            }
        } else {
            self.is(first, tokenizer::DOUBLESTAR)
                && remaining == 2
                && self.name(self.child(node, start + 1)?)
        };

        Ok(valid || self.fail("illegal variable argument trailer for varargslist"))
    }

    fn fpdef(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !self.expect_kind(node, symbol::FPDEF)
            || !self.expect_count(count == 1 || count == 3, "fpdef")
        {
            return Ok(false);
        }
        if count == 1 {
            return Ok(self.name(self.child(node, 0)?));
        }

        Ok(self.terminal(self.child(node, 0)?, tokenizer::LPAR, "(")
            && self.fplist(self.child(node, 1)?)?
            && self.terminal(self.child(node, 2)?, tokenizer::RPAR, ")"))
    }

    fn fplist(&mut self, node: u32) -> Outcome {
        self.list(node, symbol::FPLIST, "fplist", Self::fpdef)
    }

    fn classdef(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !self.shape(
            node,
            symbol::CLASSDEF,
            matches!(count, 4 | 6 | 7),
            4,
            "class",
        ) {
            return Ok(false);
        }
        if !self.keyword(self.child(node, 0)?, "class")
            || !self.name(self.child(node, 1)?)
            || !self.colon(self.child(node, count - 2)?)
            || !self.suite(self.child(node, count - 1)?)?
        {
            return Ok(false);
        }
        if count == 4 {
            return Ok(true);
        }
        if !self.terminal(self.child(node, 2)?, tokenizer::LPAR, "(") {
            return Ok(false);
        }
        if count == 7 && !self.testlist(self.child(node, 3)?)? {
            return Ok(false);
        }

        Ok(self.terminal(self.child(node, count - 3)?, tokenizer::RPAR, ")"))
    }

    fn decorator(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !matches!(count, 3 | 5 | 6) {
            return Ok(false);
        }
        if !self.terminal(self.child(node, 0)?, tokenizer::AT, "@")
            || !self.dotted_name(self.child(node, 1)?)?
            || !self.expect_kind(self.child(node, count - 1)?, tokenizer::NEWLINE)
        {
            return Ok(false);
        }
        if count == 3 {
            return Ok(true);
        }
        if !self.terminal(self.child(node, 2)?, tokenizer::LPAR, "(")
            || !self.terminal(self.child(node, count - 2)?, tokenizer::RPAR, ")")
        {
            return Ok(false);
        }

        Ok(count == 5 || self.arglist(self.child(node, 3)?)?)
    }

    fn decorators(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if count == 0 {
            return Ok(false);
        }
        for index in 0..count {
            let child = self.child(node, index)?;
            if !self.expect_kind(child, symbol::DECORATOR) || !self.decorator(child)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// The last child is read before the count is checked.
    fn decorated(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        let Some(last) = count.checked_sub(1) else {
            return Err(Undefined);
        };
        let definition = self.child(node, last)?;
        if count != 2 {
            return Ok(false);
        }
        let decorators = self.child(node, 0)?;
        if !self.expect_kind(decorators, symbol::DECORATORS) || !self.decorators(decorators)? {
            return Ok(false);
        }

        if self.is(definition, symbol::FUNCDEF) {
            self.funcdef(definition)
        } else {
            self.classdef(definition)
        }
    }
}

/// Expressions.
impl<'a> Validator<'a> {
    fn testlist(&mut self, node: u32) -> Outcome {
        self.list(node, symbol::TESTLIST, "testlist", Self::test)
    }

    fn testlist1(&mut self, node: u32) -> Outcome {
        self.list(node, symbol::TESTLIST1, "testlist1", Self::test)
    }

    fn exprlist(&mut self, node: u32) -> Outcome {
        self.list(node, symbol::EXPRLIST, "exprlist", Self::expr)
    }

    fn testlist_safe(&mut self, node: u32) -> Outcome {
        self.list(node, symbol::TESTLIST_SAFE, "testlist_safe", Self::old_test)
    }

    fn test(&mut self, node: u32) -> Outcome {
        stacker::maybe_grow(64 * 1024, 2 * 1024 * 1024, || self.test_inner(node))
    }

    fn test_inner(&mut self, node: u32) -> Outcome {
        if !self.expect_kind(node, symbol::TEST) {
            return Ok(false);
        }
        let count = self.count(node);
        if count % 2 == 0 {
            return Ok(false);
        }
        let first = self.child(node, 0)?;
        if self.is(first, symbol::LAMBDEF) {
            return Ok(count == 1 && self.lambdef(first)?);
        }
        if !self.or_test(first)? || !(count == 1 || count == 5) {
            return Ok(false);
        }

        Ok(count == 1
            || (self.keyword(self.child(node, 1)?, "if")
                && self.or_test(self.child(node, 2)?)?
                && self.keyword(self.child(node, 3)?, "else")
                && self.test(self.child(node, 4)?)?))
    }

    fn old_test(&mut self, node: u32) -> Outcome {
        if !self.expect_kind(node, symbol::OLD_TEST) || self.count(node) != 1 {
            return Ok(false);
        }
        let child = self.child(node, 0)?;

        if self.is(child, symbol::OLD_LAMBDEF) {
            self.old_lambdef(child)
        } else {
            self.or_test(child)
        }
    }

    fn lambdef(&mut self, node: u32) -> Outcome {
        self.lambda(node, "lambdef")
    }

    /// Checks its body as a `test`, as `lambdef` does.
    fn old_lambdef(&mut self, node: u32) -> Outcome {
        self.lambda(node, "old_lambdef")
    }

    /// A lambda: keyword, optional parameters, colon, body. A silent failure
    /// of the rest is
    /// reported as a wrong count unless the node has three children.
    fn lambda(&mut self, node: u32, name: &str) -> Outcome {
        let count = self.count(node);
        let valid = (count == 3 || count == 4)
            && self.keyword(self.child(node, 0)?, "lambda")
            && self.colon(self.child(node, count - 2)?)
            && self.test(self.child(node, count - 1)?)?;
        if valid && count == 4 {
            return self.varargslist(self.child(node, 1)?);
        }
        if !valid && self.error.is_none() && count != 3 {
            self.expect_count(false, name);
        }

        Ok(valid)
    }

    fn or_test(&mut self, node: u32) -> Outcome {
        if !self.expect_kind(node, symbol::OR_TEST) {
            return Ok(false);
        }

        self.chain(node, Self::and_test, |validator, operator| {
            validator.keyword(operator, "or")
        })
    }

    /// The operators are checked, but only the first operand.
    fn and_test(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !self.expect_kind(node, symbol::AND_TEST)
            || count % 2 == 0
            || !self.not_test(self.child(node, 0)?)?
        {
            return Ok(false);
        }
        for index in (1..count).step_by(2) {
            if !self.keyword(self.child(node, index)?, "and") {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn not_test(&mut self, node: u32) -> Outcome {
        if !self.expect_kind(node, symbol::NOT_TEST) {
            return Ok(false);
        }
        let count = self.count(node);
        if count == 2 {
            return Ok(self.keyword(self.child(node, 0)?, "not")
                && self.apply(Self::not_test, self.child(node, 1)?)?);
        }

        Ok(count == 1 && self.comparison(self.child(node, 0)?)?)
    }

    fn comparison(&mut self, node: u32) -> Outcome {
        if !self.expect_kind(node, symbol::COMPARISON) {
            return Ok(false);
        }
        let count = self.count(node);
        if count % 2 == 0 || !self.expr(self.child(node, 0)?)? {
            return Ok(false);
        }
        for index in (1..count).step_by(2) {
            if !self.comp_op(self.child(node, index)?)?
                || !self.expr(self.child(node, index + 1)?)?
            {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// A symbol operator is accepted by type alone, a word by its text.
    /// The accepted types include `=`.
    fn comp_op(&mut self, node: u32) -> Outcome {
        const SYMBOLS: [u16; 7] = [
            tokenizer::LESS,
            tokenizer::GREATER,
            tokenizer::EQUAL,
            tokenizer::EQEQUAL,
            tokenizer::NOTEQUAL,
            tokenizer::LESSEQUAL,
            tokenizer::GREATEREQUAL,
        ];

        let count = self.count(node);
        if !self.expect_kind(node, symbol::COMP_OP)
            || !self.expect_count(count == 1 || count == 2, "comp_op")
        {
            return Ok(false);
        }
        let first = self.child(node, 0)?;
        if count == 1 {
            if SYMBOLS.iter().any(|&kind| self.is(first, kind)) {
                return Ok(true);
            }
            if !self.is(first, tokenizer::NAME) {
                return Ok(self.fail("illegal comparison operator type"));
            }
            let text = self.text(first)?;
            if text == b"in" || text == b"is" {
                return Ok(true);
            }
            let message = [b"illegal operator '".as_slice(), text, b"'".as_slice()].concat();
            return Ok(self.fail_bytes(message));
        }
        let second = self.child(node, 1)?;
        if !self.name(first) || !self.name(second) {
            return Ok(false);
        }
        let pair = (self.text(first)?, self.text(second)?);
        if pair == (b"not".as_slice(), b"in".as_slice())
            || pair == (b"is".as_slice(), b"not".as_slice())
        {
            return Ok(true);
        }

        self.fallback(false, "unknown comparison operator");

        Ok(false)
    }

    /// Each operand is checked before the operator that precedes it.
    fn expr(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !self.expect_kind(node, symbol::EXPR)
            || count % 2 == 0
            || !self.xor_expr(self.child(node, 0)?)?
        {
            return Ok(false);
        }
        for index in (1..count).step_by(2) {
            if !self.xor_expr(self.child(node, index + 1)?)?
                || !self.terminal(self.child(node, index)?, tokenizer::VBAR, "|")
            {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn xor_expr(&mut self, node: u32) -> Outcome {
        if !self.expect_kind(node, symbol::XOR_EXPR) {
            return Ok(false);
        }

        self.chain(node, Self::and_expr, |validator, operator| {
            validator.terminal(operator, tokenizer::CIRCUMFLEX, "^")
        })
    }

    fn and_expr(&mut self, node: u32) -> Outcome {
        if !self.expect_kind(node, symbol::AND_EXPR) {
            return Ok(false);
        }

        self.chain(node, Self::shift_expr, |validator, operator| {
            validator.terminal(operator, tokenizer::AMPER, "&")
        })
    }

    fn shift_expr(&mut self, node: u32) -> Outcome {
        if !self.expect_kind(node, symbol::SHIFT_EXPR) {
            return Ok(false);
        }

        self.chain(node, Self::arith_expr, |validator, operator| {
            validator.is(operator, tokenizer::LEFTSHIFT)
                || validator.expect_kind(operator, tokenizer::RIGHTSHIFT)
        })
    }

    fn arith_expr(&mut self, node: u32) -> Outcome {
        if !self.expect_kind(node, symbol::ARITH_EXPR) {
            return Ok(false);
        }

        self.chain(node, Self::term, |validator, operator| {
            validator.is(operator, tokenizer::PLUS)
                || validator.expect_kind(operator, tokenizer::MINUS)
        })
    }

    /// An operator of another type fails without a message.
    fn term(&mut self, node: u32) -> Outcome {
        if !self.expect_kind(node, symbol::TERM) {
            return Ok(false);
        }

        self.chain(node, Self::factor, |validator, operator| {
            [
                tokenizer::STAR,
                tokenizer::SLASH,
                tokenizer::PERCENT,
                tokenizer::DOUBLESLASH,
            ]
            .iter()
            .any(|&kind| validator.is(operator, kind))
        })
    }

    fn factor(&mut self, node: u32) -> Outcome {
        if !self.expect_kind(node, symbol::FACTOR) {
            return Ok(false);
        }
        let count = self.count(node);
        if count == 2 {
            let operator = self.child(node, 0)?;
            let unary = self.is(operator, tokenizer::PLUS)
                || self.is(operator, tokenizer::MINUS)
                || self.is(operator, tokenizer::TILDE);
            return Ok(unary && self.apply(Self::factor, self.child(node, 1)?)?);
        }

        Ok(count == 1 && self.power(self.child(node, 0)?)?)
    }

    /// An atom, its trailers, and any power operators with their operands.
    fn power(&mut self, node: u32) -> Outcome {
        if !self.expect_kind(node, symbol::POWER) {
            return Ok(false);
        }
        let count = self.count(node);
        if count == 0 || !self.atom(self.child(node, 0)?)? {
            return Ok(false);
        }
        let mut index = 1;
        while index < count && self.is(self.child(node, index)?, symbol::TRAILER) {
            if !self.trailer(self.child(node, index)?)? {
                return Ok(false);
            }
            index += 1;
        }
        if (count - index) % 2 != 0 {
            return Ok(self.fail("illegal number of nodes for 'power'"));
        }
        while index < count {
            if !self.terminal(self.child(node, index)?, tokenizer::DOUBLESTAR, "**")
                || !self.apply(Self::factor, self.child(node, index + 1)?)?
            {
                return Ok(false);
            }
            index += 2;
        }

        Ok(true)
    }

    fn atom(&mut self, node: u32) -> Outcome {
        if !self.expect_kind(node, symbol::ATOM) {
            return Ok(false);
        }
        let count = self.count(node);
        if !self.expect_count(count >= 1, "atom") {
            return Ok(false);
        }
        let first = self.child(node, 0)?;
        match self.kind(first) {
            kind if kind == i32::from(tokenizer::NAME) || kind == i32::from(tokenizer::NUMBER) => {
                Ok(count == 1)
            }
            kind if kind == i32::from(tokenizer::STRING) => {
                for index in 1..count {
                    if !self.expect_kind(self.child(node, index)?, tokenizer::STRING) {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            kind if kind == i32::from(tokenizer::LPAR) => {
                if count > 3 || !self.terminal(self.child(node, count - 1)?, tokenizer::RPAR, ")") {
                    return Ok(false);
                }
                if count != 3 {
                    return Ok(true);
                }
                let inner = self.child(node, 1)?;
                if self.is(inner, symbol::YIELD_EXPR) {
                    self.yield_expr(inner)
                } else {
                    self.testlist_comp(inner)
                }
            }
            kind if kind == i32::from(tokenizer::LSQB) => {
                if !(count == 2 || count == 3) {
                    return Ok(self.fail("illegal list display atom"));
                }
                if count == 3 && !self.listmaker(self.child(node, 1)?)? {
                    return Ok(false);
                }
                Ok(self.expect_kind(self.child(node, count - 1)?, tokenizer::RSQB))
            }
            kind if kind == i32::from(tokenizer::LBRACE) => {
                if count > 3 || !self.expect_kind(self.child(node, count - 1)?, tokenizer::RBRACE) {
                    return Ok(false);
                }
                if count != 3 {
                    return Ok(true);
                }
                let inner = self.child(node, 1)?;
                Ok(
                    self.expect_kind(inner, symbol::DICTORSETMAKER)
                        && self.dictorsetmaker(inner)?,
                )
            }
            kind if kind == i32::from(tokenizer::BACKQUOTE) => Ok(count == 3
                && self.testlist1(self.child(node, 1)?)?
                && self.expect_kind(self.child(node, 2)?, tokenizer::BACKQUOTE)),
            _ => Ok(false),
        }
    }

    fn listmaker(&mut self, node: u32) -> Outcome {
        self.display(node, "listmaker", symbol::LIST_FOR, Self::list_for)
    }

    fn testlist_comp(&mut self, node: u32) -> Outcome {
        self.display(node, "testlist_comp", symbol::COMP_FOR, Self::comp_for)
    }

    /// A test followed by a comprehension, or by further comma-separated
    /// tests. Before a comprehension
    /// the first test's failure is set aside. A failure before the last
    /// one or two children is reported as trailing nodes.
    fn display(&mut self, node: u32, name: &str, comprehension: u16, rule: Rule<'a>) -> Outcome {
        let count = self.count(node);
        if count == 0 {
            return Ok(self.fail(&format!("illegal trailing nodes for {name}")));
        }
        let first = self.test(self.child(node, 0)?)?;
        if count == 2 && self.is(self.child(node, 1)?, comprehension) {
            return self.apply(rule, self.child(node, 1)?);
        }
        if count == 1 {
            return Ok(first);
        }

        let mut valid = first;
        let mut index = 1;
        while valid && index + 2 < count {
            valid =
                self.comma(self.child(node, index)?) && self.test(self.child(node, index + 1)?)?;
            index += 2;
        }
        if !valid {
            return Ok(self.fail(&format!("illegal trailing nodes for {name}")));
        }
        if index + 1 == count {
            return Ok(self.comma(self.child(node, index)?));
        }

        Ok(self.comma(self.child(node, index)?) && self.test(self.child(node, index + 1)?)?)
    }

    /// Dictionary entries or set elements, each form either listed with
    /// commas or followed by a comprehension.
    fn dictorsetmaker(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        let first = self.child(node, 0)?;
        if count == 1 {
            return self.test(first);
        }
        let second = self.child(node, 1)?;
        if self.is(second, symbol::COMP_FOR) {
            return Ok(self.test(first)? && self.comp_for(second)?);
        }
        if self.is(second, tokenizer::COMMA) {
            let mut index = 0;
            while index + 1 < count {
                if !self.test(self.child(node, index)?)?
                    || !self.comma(self.child(node, index + 1)?)
                {
                    return Ok(false);
                }
                index += 2;
            }
            if index < count && !self.test(self.child(node, index)?)? {
                return Ok(false);
            }
            return Ok(true);
        }

        if count < 3 {
            return Ok(self.fail("illegal number of nodes for dictorsetmaker"));
        }
        if !(self.test(first)? && self.colon(second) && self.test(self.child(node, 2)?)?) {
            return Ok(false);
        }
        if count > 3 && self.is(self.child(node, 3)?, symbol::COMP_FOR) {
            return self.comp_for(self.child(node, 3)?);
        }
        let mut index = 3;
        while index + 4 <= count {
            let valid = self.comma(self.child(node, index)?)
                && self.test(self.child(node, index + 1)?)?
                && self.colon(self.child(node, index + 2)?)
                && self.test(self.child(node, index + 3)?)?;
            if !valid {
                return Ok(false);
            }
            index += 4;
        }
        if index + 1 == count {
            return Ok(self.comma(self.child(node, index)?));
        }

        Ok(index == count || self.fail("illegal trailing nodes for dictorsetmaker"))
    }

    fn trailer(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !self.expect_count(count == 2 || count == 3, "trailer") {
            return Ok(false);
        }
        let first = self.child(node, 0)?;
        match self.kind(first) {
            kind if kind == i32::from(tokenizer::LPAR) => {
                Ok(
                    self.terminal(self.child(node, count - 1)?, tokenizer::RPAR, ")")
                        && (count == 2 || self.arglist(self.child(node, 1)?)?),
                )
            }
            kind if kind == i32::from(tokenizer::LSQB) => Ok(self
                .expect_count(count == 3, "trailer")
                && self.subscriptlist(self.child(node, 1)?)?
                && self.expect_kind(self.child(node, 2)?, tokenizer::RSQB)),
            kind if kind == i32::from(tokenizer::DOT) => {
                Ok(self.expect_count(count == 2, "trailer") && self.name(self.child(node, 1)?))
            }
            _ => Ok(false),
        }
    }

    fn subscriptlist(&mut self, node: u32) -> Outcome {
        self.list(
            node,
            symbol::SUBSCRIPTLIST,
            "subscriptlist",
            Self::subscript,
        )
    }

    /// An ellipsis, an index, or a slice with optional bounds and step.
    /// Children after
    /// a slice step are not checked.
    fn subscript(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !self.expect_kind(node, symbol::SUBSCRIPT) {
            return Ok(false);
        }
        if count == 0 || count > 4 {
            self.fallback(false, "invalid number of arguments for subscript node");
            return Ok(false);
        }
        let first = self.child(node, 0)?;
        if self.is(first, tokenizer::DOT) {
            return Ok(self.expect_count(count == 3, "subscript")
                && self.terminal(first, tokenizer::DOT, ".")
                && self.terminal(self.child(node, 1)?, tokenizer::DOT, ".")
                && self.terminal(self.child(node, 2)?, tokenizer::DOT, "."));
        }
        if count == 1 {
            if self.is(first, symbol::TEST) {
                return self.test(first);
            }
            return Ok(self.colon(first));
        }

        let mut index = 0;
        if count == 4 || !self.is(first, tokenizer::COLON) {
            if !self.test(first)? {
                return Ok(false);
            }
            index = 1;
        }
        if !self.colon(self.child(node, index)?) {
            return Ok(false);
        }
        index += 1;
        if index < count && self.is(self.child(node, index)?, symbol::TEST) {
            if !self.test(self.child(node, index)?)? {
                return Ok(false);
            }
            index += 1;
        }

        Ok(index >= count || self.sliceop(self.child(node, index)?)?)
    }

    fn sliceop(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !self.expect_count(count == 1 || count == 2, "sliceop")
            || !self.expect_kind(node, symbol::SLICEOP)
            || !self.colon(self.child(node, 0)?)
        {
            return Ok(false);
        }

        Ok(count == 1 || self.test(self.child(node, 1)?)?)
    }

    /// With more than one child, only generator arguments are checked:
    /// each needs parentheses of its own.
    fn arglist(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !self.expect_count(count >= 1, "arglist") {
            return Ok(false);
        }
        if count > 1 {
            for index in 0..count {
                let child = self.child(node, index)?;
                if self.is(child, symbol::ARGUMENT)
                    && self.count(child) >= 2
                    && self.is(self.child(child, 1)?, symbol::COMP_FOR)
                {
                    return Ok(self.fail("need '(', ')' for generator expression"));
                }
            }
            return Ok(true);
        }
        let only = self.child(node, 0)?;
        match self.kind(only) {
            kind if kind == i32::from(symbol::ARGUMENT) => self.argument(only),
            kind if kind == i32::from(tokenizer::STAR) => {
                Ok(self.fail("illegal use of '*' in arglist"))
            }
            kind if kind == i32::from(tokenizer::DOUBLESTAR) => {
                Ok(self.fail("illegal use of '**' in arglist"))
            }
            _ => Ok(self.fail("illegal arglist specification")),
        }
    }

    fn argument(&mut self, node: u32) -> Outcome {
        let count = self.count(node);
        if !matches!(count, 1 | 2 | 3) || !self.test(self.child(node, 0)?)? {
            return Ok(false);
        }
        if count == 2 {
            return self.comp_for(self.child(node, 1)?);
        }

        Ok(count == 1
            || (self.terminal(self.child(node, 1)?, tokenizer::EQUAL, "=")
                && self.test(self.child(node, 2)?)?))
    }

    fn list_iter(&mut self, node: u32) -> Outcome {
        self.iteration(
            node,
            symbol::LIST_ITER,
            "list_iter",
            symbol::LIST_FOR,
            Self::list_for,
            Self::list_if,
        )
    }

    fn comp_iter(&mut self, node: u32) -> Outcome {
        self.iteration(
            node,
            symbol::COMP_ITER,
            "comp_iter",
            symbol::COMP_FOR,
            Self::comp_for,
            Self::comp_if,
        )
    }

    /// `for_rule | if_rule`. A wrong type or count is reported but only
    /// steers the first child to `if_rule`.
    fn iteration(
        &mut self,
        node: u32,
        kind: u16,
        name: &str,
        for_kind: u16,
        for_rule: Rule<'a>,
        if_rule: Rule<'a>,
    ) -> Outcome {
        let single = self.expect_kind(node, kind) && self.expect_count(self.count(node) == 1, name);
        let child = self.child(node, 0)?;

        if single && self.is(child, for_kind) {
            self.apply(for_rule, child)
        } else {
            self.apply(if_rule, child)
        }
    }

    fn list_for(&mut self, node: u32) -> Outcome {
        self.for_clause(node, "list_for", Self::testlist_safe, Self::list_iter)
    }

    fn comp_for(&mut self, node: u32) -> Outcome {
        self.for_clause(node, "comp_for", Self::or_test, Self::comp_iter)
    }

    /// A `for` clause with its targets, iterable, and optional following
    /// clause; the following clause is
    /// checked first.
    fn for_clause(&mut self, node: u32, name: &str, iterable: Rule<'a>, iter: Rule<'a>) -> Outcome {
        let count = self.count(node);
        if !self.expect_count(count == 4 || count == 5, name) {
            return Ok(false);
        }
        if count == 5 && !self.apply(iter, self.child(node, 4)?)? {
            return Ok(false);
        }

        Ok(self.keyword(self.child(node, 0)?, "for")
            && self.exprlist(self.child(node, 1)?)?
            && self.keyword(self.child(node, 2)?, "in")
            && self.apply(iterable, self.child(node, 3)?)?)
    }

    fn list_if(&mut self, node: u32) -> Outcome {
        self.if_clause(node, "list_if", Self::list_iter)
    }

    fn comp_if(&mut self, node: u32) -> Outcome {
        self.if_clause(node, "comp_if", Self::comp_iter)
    }

    /// An `if` clause with its condition and optional following clause; the
    /// following clause is checked first.
    fn if_clause(&mut self, node: u32, name: &str, iter: Rule<'a>) -> Outcome {
        let count = self.count(node);
        if !self.expect_count(count == 2 || count == 3, name) {
            return Ok(false);
        }
        if count == 3 && !self.apply(iter, self.child(node, 2)?)? {
            return Ok(false);
        }

        Ok(self.keyword(self.child(node, 0)?, "if") && self.old_test(self.child(node, 1)?)?)
    }

    fn yield_expr(&mut self, node: u32) -> Outcome {
        if !self.expect_kind(node, symbol::YIELD_EXPR) {
            return Ok(false);
        }
        let count = self.count(node);
        if !(count == 1 || count == 2) || !self.keyword(self.child(node, 0)?, "yield") {
            return Ok(false);
        }

        Ok(count == 1 || self.testlist(self.child(node, 1)?)?)
    }
}
