//! The grammar of the prolog and of DTDs as a state machine over tokens. Each
//! token moves the machine and yields the role that token plays, which tells
//! the prolog processor what to record or report.
//!
//! White space between the parts of a declaration is not checked here; the
//! tokenizer already requires it where names and literals would run together.

use super::scan::Tok;

/// What a token means to the prolog processor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Role {
    Error,
    /// Nothing to record outside any declaration.
    None,
    XmlDecl,
    TextDecl,
    InstanceStart,
    Pi,
    Comment,

    /// A token inside a DOCTYPE declaration with no further meaning.
    DoctypeNone,
    DoctypeName,
    DoctypePublicId,
    DoctypeSystemId,
    DoctypeInternalSubset,
    DoctypeClose,

    EntityNone,
    GeneralEntityName,
    ParamEntityName,
    EntityValue,
    EntityPublicId,
    EntitySystemId,
    EntityComplete,
    EntityNotationName,

    NotationNone,
    NotationName,
    NotationPublicId,
    NotationSystemId,
    NotationNoSystemId,

    AttlistNone,
    AttlistElementName,
    AttributeName,
    AttributeType(AttributeType),
    AttributeEnumValue,
    AttributeNotationValue,
    ImpliedAttributeValue,
    RequiredAttributeValue,
    DefaultAttributeValue,
    FixedAttributeValue,

    ElementNone,
    ElementName,
    ContentAny,
    ContentEmpty,
    ContentPcdata,
    GroupOpen,
    GroupClose(Quant),
    GroupChoice,
    GroupSequence,
    ContentElement(Quant),

    ParamEntityRef,
    InnerParamEntityRef,
    IncludeSection,
    IgnoreSection,
}

/// A declared attribute type named by a keyword.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum AttributeType {
    Cdata,
    Id,
    Idref,
    Idrefs,
    Entity,
    Entities,
    Nmtoken,
    Nmtokens,
}

impl AttributeType {
    pub(super) fn keyword(self) -> &'static [u8] {
        match self {
            Self::Cdata => b"CDATA",
            Self::Id => b"ID",
            Self::Idref => b"IDREF",
            Self::Idrefs => b"IDREFS",
            Self::Entity => b"ENTITY",
            Self::Entities => b"ENTITIES",
            Self::Nmtoken => b"NMTOKEN",
            Self::Nmtokens => b"NMTOKENS",
        }
    }
}

/// The occurrence suffix of a content particle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Quant {
    One,
    Opt,
    Rep,
    Plus,
}

/// The kind of declaration whose closing `>` the machine expects.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DeclKind {
    Entity,
    Notation,
    Element,
}

/// A position in the grammar.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    /// Start of the document entity.
    DocumentStart,
    /// After the XML declaration or other prolog material, before any DOCTYPE.
    BeforeDoctype,
    /// After the DOCTYPE declaration.
    AfterDoctype,

    DoctypeKeyword,
    DoctypeAfterName,
    DoctypeAfterPublic,
    DoctypeSystemLiteral,
    DoctypeAfterExternalId,
    DoctypeAfterSubset,

    /// Between declarations of the internal subset.
    InternalSubset,
    /// Start of an external subset or external parameter entity.
    ExternalStart,
    /// Between declarations of an external subset or parameter entity.
    ExternalSubset,

    EntityKeyword,
    EntityAfterPercent,
    GeneralEntityAfterName,
    GeneralEntityAfterPublic,
    GeneralEntitySystemLiteral,
    GeneralEntityAfterSystem,
    GeneralEntityAfterNdata,
    ParamEntityAfterName,
    ParamEntityAfterPublic,
    ParamEntitySystemLiteral,
    ParamEntityAfterSystem,

    NotationKeyword,
    NotationAfterName,
    NotationAfterPublic,
    NotationSystemLiteral,
    NotationAfterPublicLiteral,

    AttlistKeyword,
    AttlistAfterElement,
    AttributeTypeExpected,
    EnumValueExpected,
    EnumValueAfter,
    NotationListOpen,
    NotationValueExpected,
    NotationValueAfter,
    DefaultDeclExpected,
    FixedValueExpected,

    ElementKeyword,
    ElementContentSpec,
    ElementFirstParticle,
    MixedAfterPcdata,
    MixedNameExpected,
    MixedAfterName,
    ParticleExpected,
    ParticleAfter,

    CondSectKeyword,
    IncludeBracket,
    IgnoreBracket,

    DeclClose(DeclKind),
    Failed,
}

/// The grammar machine for one entity.
#[derive(Clone, Debug)]
pub(super) struct Grammar {
    state: State,
    /// Open parentheses of the content model being read.
    pub level: usize,
    /// Open INCLUDE sections.
    include_depth: usize,
    /// Reading the document entity, where parameter entity references may
    /// only occur between declarations.
    document_entity: bool,
}

impl Grammar {
    pub(super) fn new() -> Self {
        Self { state: State::DocumentStart, level: 0, include_depth: 0, document_entity: true }
    }

    /// A machine for an external subset or external parameter entity.
    pub(super) fn new_external() -> Self {
        Self { state: State::ExternalStart, level: 0, include_depth: 0, document_entity: false }
    }

    /// The role of `tok`, whose text is `text` (keywords are matched on it,
    /// without a leading `#` for `PoundName`).
    pub(super) fn role(&mut self, tok: Tok, text: &[u8]) -> Role {
        let (role, next) = self.step(tok, text);
        match next {
            Some(state) => self.state = state,
            None => return self.fallback(tok),
        }

        role
    }

    /// The role of a token the current state does not accept.
    fn fallback(&mut self, tok: Tok) -> Role {
        if !self.document_entity && tok == Tok::ParamEntityRef {
            return Role::InnerParamEntityRef;
        }
        self.state = State::Failed;

        Role::Error
    }

    /// The role of `tok` and the next state, or `None` when the state does not accept it.
    fn step(&mut self, tok: Tok, text: &[u8]) -> (Role, Option<State>) {
        use State as S;

        let keep = Some(self.state);
        let is_name = matches!(tok, Tok::Name | Tok::PrefixedName);
        let keyword = |word: &[u8]| tok == Tok::Name && text == word;

        match self.state {
            S::DocumentStart | S::BeforeDoctype | S::AfterDoctype => {
                let after = if self.state == S::DocumentStart { S::BeforeDoctype } else { self.state };
                match tok {
                    Tok::Space => (Role::None, Some(after)),
                    Tok::XmlDecl if self.state == S::DocumentStart => (Role::XmlDecl, Some(S::BeforeDoctype)),
                    Tok::Pi => (Role::Pi, Some(after)),
                    Tok::Comment => (Role::Comment, Some(after)),
                    Tok::Bom if self.state == S::DocumentStart => (Role::None, keep),
                    Tok::DeclOpen if self.state != S::AfterDoctype && text == b"DOCTYPE" => (Role::DoctypeNone, Some(S::DoctypeKeyword)),
                    Tok::InstanceStart => (Role::InstanceStart, keep),
                    _ => (Role::Error, None),
                }
            }

            S::DoctypeKeyword => match tok {
                Tok::Space => (Role::DoctypeNone, keep),
                _ if is_name => (Role::DoctypeName, Some(S::DoctypeAfterName)),
                _ => (Role::Error, None),
            },
            S::DoctypeAfterName => match tok {
                Tok::Space => (Role::DoctypeNone, keep),
                Tok::OpenBracket => (Role::DoctypeInternalSubset, Some(S::InternalSubset)),
                Tok::DeclClose => (Role::DoctypeClose, Some(S::AfterDoctype)),
                _ if keyword(b"SYSTEM") => (Role::DoctypeNone, Some(S::DoctypeSystemLiteral)),
                _ if keyword(b"PUBLIC") => (Role::DoctypeNone, Some(S::DoctypeAfterPublic)),
                _ => (Role::Error, None),
            },
            S::DoctypeAfterPublic => match tok {
                Tok::Space => (Role::DoctypeNone, keep),
                Tok::Literal => (Role::DoctypePublicId, Some(S::DoctypeSystemLiteral)),
                _ => (Role::Error, None),
            },
            S::DoctypeSystemLiteral => match tok {
                Tok::Space => (Role::DoctypeNone, keep),
                Tok::Literal => (Role::DoctypeSystemId, Some(S::DoctypeAfterExternalId)),
                _ => (Role::Error, None),
            },
            S::DoctypeAfterExternalId => match tok {
                Tok::Space => (Role::DoctypeNone, keep),
                Tok::OpenBracket => (Role::DoctypeInternalSubset, Some(S::InternalSubset)),
                Tok::DeclClose => (Role::DoctypeClose, Some(S::AfterDoctype)),
                _ => (Role::Error, None),
            },
            S::DoctypeAfterSubset => match tok {
                Tok::Space => (Role::DoctypeNone, keep),
                Tok::DeclClose => (Role::DoctypeClose, Some(S::AfterDoctype)),
                _ => (Role::Error, None),
            },

            S::InternalSubset => self.between_declarations(tok, text),
            S::ExternalStart => {
                if tok == Tok::XmlDecl {
                    return (Role::TextDecl, Some(S::ExternalSubset));
                }
                self.state = S::ExternalSubset;
                self.step(tok, text)
            }
            S::ExternalSubset => match tok {
                Tok::CondSectOpen => (Role::None, Some(S::CondSectKeyword)),
                Tok::CondSectClose if self.include_depth > 0 => {
                    self.include_depth -= 1;
                    (Role::None, keep)
                }
                Tok::CondSectClose => (Role::Error, None),
                Tok::Space => (Role::None, keep),
                Tok::CloseBracket => (Role::Error, None),
                Tok::Empty if self.include_depth > 0 => (Role::Error, None),
                Tok::Empty => (Role::None, keep),
                _ => self.between_declarations(tok, text),
            },

            S::EntityKeyword => match tok {
                Tok::Space => (Role::EntityNone, keep),
                Tok::Percent => (Role::EntityNone, Some(S::EntityAfterPercent)),
                Tok::Name => (Role::GeneralEntityName, Some(S::GeneralEntityAfterName)),
                _ => (Role::Error, None),
            },
            S::EntityAfterPercent => match tok {
                Tok::Space => (Role::EntityNone, keep),
                Tok::Name => (Role::ParamEntityName, Some(S::ParamEntityAfterName)),
                _ => (Role::Error, None),
            },
            S::GeneralEntityAfterName => match tok {
                Tok::Space => (Role::EntityNone, keep),
                Tok::Literal => (Role::EntityValue, Some(S::DeclClose(DeclKind::Entity))),
                _ if keyword(b"SYSTEM") => (Role::EntityNone, Some(S::GeneralEntitySystemLiteral)),
                _ if keyword(b"PUBLIC") => (Role::EntityNone, Some(S::GeneralEntityAfterPublic)),
                _ => (Role::Error, None),
            },
            S::GeneralEntityAfterPublic => match tok {
                Tok::Space => (Role::EntityNone, keep),
                Tok::Literal => (Role::EntityPublicId, Some(S::GeneralEntitySystemLiteral)),
                _ => (Role::Error, None),
            },
            S::GeneralEntitySystemLiteral => match tok {
                Tok::Space => (Role::EntityNone, keep),
                Tok::Literal => (Role::EntitySystemId, Some(S::GeneralEntityAfterSystem)),
                _ => (Role::Error, None),
            },
            S::GeneralEntityAfterSystem => match tok {
                Tok::Space => (Role::EntityNone, keep),
                Tok::DeclClose => (Role::EntityComplete, Some(self.subset_state())),
                _ if keyword(b"NDATA") => (Role::EntityNone, Some(S::GeneralEntityAfterNdata)),
                _ => (Role::Error, None),
            },
            S::GeneralEntityAfterNdata => match tok {
                Tok::Space => (Role::EntityNone, keep),
                Tok::Name => (Role::EntityNotationName, Some(S::DeclClose(DeclKind::Entity))),
                _ => (Role::Error, None),
            },
            S::ParamEntityAfterName => match tok {
                Tok::Space => (Role::EntityNone, keep),
                Tok::Literal => (Role::EntityValue, Some(S::DeclClose(DeclKind::Entity))),
                _ if keyword(b"SYSTEM") => (Role::EntityNone, Some(S::ParamEntitySystemLiteral)),
                _ if keyword(b"PUBLIC") => (Role::EntityNone, Some(S::ParamEntityAfterPublic)),
                _ => (Role::Error, None),
            },
            S::ParamEntityAfterPublic => match tok {
                Tok::Space => (Role::EntityNone, keep),
                Tok::Literal => (Role::EntityPublicId, Some(S::ParamEntitySystemLiteral)),
                _ => (Role::Error, None),
            },
            S::ParamEntitySystemLiteral => match tok {
                Tok::Space => (Role::EntityNone, keep),
                Tok::Literal => (Role::EntitySystemId, Some(S::ParamEntityAfterSystem)),
                _ => (Role::Error, None),
            },
            S::ParamEntityAfterSystem => match tok {
                Tok::Space => (Role::EntityNone, keep),
                Tok::DeclClose => (Role::EntityComplete, Some(self.subset_state())),
                _ => (Role::Error, None),
            },

            S::NotationKeyword => match tok {
                Tok::Space => (Role::NotationNone, keep),
                Tok::Name => (Role::NotationName, Some(S::NotationAfterName)),
                _ => (Role::Error, None),
            },
            S::NotationAfterName => match tok {
                Tok::Space => (Role::NotationNone, keep),
                _ if keyword(b"SYSTEM") => (Role::NotationNone, Some(S::NotationSystemLiteral)),
                _ if keyword(b"PUBLIC") => (Role::NotationNone, Some(S::NotationAfterPublic)),
                _ => (Role::Error, None),
            },
            S::NotationAfterPublic => match tok {
                Tok::Space => (Role::NotationNone, keep),
                Tok::Literal => (Role::NotationPublicId, Some(S::NotationAfterPublicLiteral)),
                _ => (Role::Error, None),
            },
            S::NotationSystemLiteral => match tok {
                Tok::Space => (Role::NotationNone, keep),
                Tok::Literal => (Role::NotationSystemId, Some(S::DeclClose(DeclKind::Notation))),
                _ => (Role::Error, None),
            },
            S::NotationAfterPublicLiteral => match tok {
                Tok::Space => (Role::NotationNone, keep),
                Tok::Literal => (Role::NotationSystemId, Some(S::DeclClose(DeclKind::Notation))),
                Tok::DeclClose => (Role::NotationNoSystemId, Some(self.subset_state())),
                _ => (Role::Error, None),
            },

            S::AttlistKeyword => match tok {
                Tok::Space => (Role::AttlistNone, keep),
                _ if is_name => (Role::AttlistElementName, Some(S::AttlistAfterElement)),
                _ => (Role::Error, None),
            },
            S::AttlistAfterElement => match tok {
                Tok::Space => (Role::AttlistNone, keep),
                Tok::DeclClose => (Role::AttlistNone, Some(self.subset_state())),
                _ if is_name => (Role::AttributeName, Some(S::AttributeTypeExpected)),
                _ => (Role::Error, None),
            },
            S::AttributeTypeExpected => {
                const TYPES: [AttributeType; 8] = [
                    AttributeType::Cdata,
                    AttributeType::Id,
                    AttributeType::Idref,
                    AttributeType::Idrefs,
                    AttributeType::Entity,
                    AttributeType::Entities,
                    AttributeType::Nmtoken,
                    AttributeType::Nmtokens,
                ];
                match tok {
                    Tok::Space => (Role::AttlistNone, keep),
                    Tok::OpenParen => (Role::AttlistNone, Some(S::EnumValueExpected)),
                    Tok::Name => {
                        if let Some(kind) = TYPES.into_iter().find(|kind| kind.keyword() == text) {
                            return (Role::AttributeType(kind), Some(S::DefaultDeclExpected));
                        }
                        if text == b"NOTATION" {
                            return (Role::AttlistNone, Some(S::NotationListOpen));
                        }
                        (Role::Error, None)
                    }
                    _ => (Role::Error, None),
                }
            }
            S::EnumValueExpected => match tok {
                Tok::Space => (Role::AttlistNone, keep),
                Tok::Nmtoken | Tok::Name | Tok::PrefixedName => (Role::AttributeEnumValue, Some(S::EnumValueAfter)),
                _ => (Role::Error, None),
            },
            S::EnumValueAfter => match tok {
                Tok::Space => (Role::AttlistNone, keep),
                Tok::CloseParen => (Role::AttlistNone, Some(S::DefaultDeclExpected)),
                Tok::Or => (Role::AttlistNone, Some(S::EnumValueExpected)),
                _ => (Role::Error, None),
            },
            S::NotationListOpen => match tok {
                Tok::Space => (Role::AttlistNone, keep),
                Tok::OpenParen => (Role::AttlistNone, Some(S::NotationValueExpected)),
                _ => (Role::Error, None),
            },
            S::NotationValueExpected => match tok {
                Tok::Space => (Role::AttlistNone, keep),
                Tok::Name => (Role::AttributeNotationValue, Some(S::NotationValueAfter)),
                _ => (Role::Error, None),
            },
            S::NotationValueAfter => match tok {
                Tok::Space => (Role::AttlistNone, keep),
                Tok::CloseParen => (Role::AttlistNone, Some(S::DefaultDeclExpected)),
                Tok::Or => (Role::AttlistNone, Some(S::NotationValueExpected)),
                _ => (Role::Error, None),
            },
            S::DefaultDeclExpected => match tok {
                Tok::Space => (Role::AttlistNone, keep),
                Tok::PoundName if text == b"IMPLIED" => (Role::ImpliedAttributeValue, Some(S::AttlistAfterElement)),
                Tok::PoundName if text == b"REQUIRED" => (Role::RequiredAttributeValue, Some(S::AttlistAfterElement)),
                Tok::PoundName if text == b"FIXED" => (Role::AttlistNone, Some(S::FixedValueExpected)),
                Tok::Literal => (Role::DefaultAttributeValue, Some(S::AttlistAfterElement)),
                _ => (Role::Error, None),
            },
            S::FixedValueExpected => match tok {
                Tok::Space => (Role::AttlistNone, keep),
                Tok::Literal => (Role::FixedAttributeValue, Some(S::AttlistAfterElement)),
                _ => (Role::Error, None),
            },

            S::ElementKeyword => match tok {
                Tok::Space => (Role::ElementNone, keep),
                _ if is_name => (Role::ElementName, Some(S::ElementContentSpec)),
                _ => (Role::Error, None),
            },
            S::ElementContentSpec => match tok {
                Tok::Space => (Role::ElementNone, keep),
                _ if keyword(b"EMPTY") => (Role::ContentEmpty, Some(S::DeclClose(DeclKind::Element))),
                _ if keyword(b"ANY") => (Role::ContentAny, Some(S::DeclClose(DeclKind::Element))),
                Tok::OpenParen => {
                    self.level = 1;
                    (Role::GroupOpen, Some(S::ElementFirstParticle))
                }
                _ => (Role::Error, None),
            },
            S::ElementFirstParticle => match tok {
                Tok::Space => (Role::ElementNone, keep),
                Tok::PoundName if text == b"PCDATA" => (Role::ContentPcdata, Some(S::MixedAfterPcdata)),
                Tok::OpenParen => {
                    self.level = 2;
                    (Role::GroupOpen, Some(S::ParticleExpected))
                }
                _ => match particle(tok) {
                    Some(quant) => (Role::ContentElement(quant), Some(S::ParticleAfter)),
                    None => (Role::Error, None),
                },
            },
            S::MixedAfterPcdata => match tok {
                Tok::Space => (Role::ElementNone, keep),
                Tok::CloseParen => (Role::GroupClose(Quant::One), Some(S::DeclClose(DeclKind::Element))),
                Tok::CloseParenAsterisk => (Role::GroupClose(Quant::Rep), Some(S::DeclClose(DeclKind::Element))),
                Tok::Or => (Role::ElementNone, Some(S::MixedNameExpected)),
                _ => (Role::Error, None),
            },
            S::MixedNameExpected => match tok {
                Tok::Space => (Role::ElementNone, keep),
                _ if is_name => (Role::ContentElement(Quant::One), Some(S::MixedAfterName)),
                _ => (Role::Error, None),
            },
            S::MixedAfterName => match tok {
                Tok::Space => (Role::ElementNone, keep),
                Tok::CloseParenAsterisk => (Role::GroupClose(Quant::Rep), Some(S::DeclClose(DeclKind::Element))),
                Tok::Or => (Role::ElementNone, Some(S::MixedNameExpected)),
                _ => (Role::Error, None),
            },
            S::ParticleExpected => match tok {
                Tok::Space => (Role::ElementNone, keep),
                Tok::OpenParen => {
                    self.level += 1;
                    (Role::GroupOpen, keep)
                }
                _ => match particle(tok) {
                    Some(quant) => (Role::ContentElement(quant), Some(S::ParticleAfter)),
                    None => (Role::Error, None),
                },
            },
            S::ParticleAfter => {
                let quant = match tok {
                    Tok::Space => return (Role::ElementNone, keep),
                    Tok::Comma => return (Role::GroupSequence, Some(S::ParticleExpected)),
                    Tok::Or => return (Role::GroupChoice, Some(S::ParticleExpected)),
                    Tok::CloseParen => Quant::One,
                    Tok::CloseParenAsterisk => Quant::Rep,
                    Tok::CloseParenQuestion => Quant::Opt,
                    Tok::CloseParenPlus => Quant::Plus,
                    _ => return (Role::Error, None),
                };
                self.level -= 1;
                let next = if self.level == 0 { S::DeclClose(DeclKind::Element) } else { S::ParticleAfter };
                (Role::GroupClose(quant), Some(next))
            }

            S::CondSectKeyword => match tok {
                Tok::Space => (Role::None, keep),
                _ if keyword(b"INCLUDE") => (Role::None, Some(S::IncludeBracket)),
                _ if keyword(b"IGNORE") => (Role::None, Some(S::IgnoreBracket)),
                _ => (Role::Error, None),
            },
            S::IncludeBracket => match tok {
                Tok::Space => (Role::None, keep),
                Tok::OpenBracket => {
                    self.include_depth += 1;
                    (Role::IncludeSection, Some(S::ExternalSubset))
                }
                _ => (Role::Error, None),
            },
            S::IgnoreBracket => match tok {
                Tok::Space => (Role::None, keep),
                Tok::OpenBracket => (Role::IgnoreSection, Some(S::ExternalSubset)),
                _ => (Role::Error, None),
            },

            S::DeclClose(kind) => {
                let none = match kind {
                    DeclKind::Entity => Role::EntityNone,
                    DeclKind::Notation => Role::NotationNone,
                    DeclKind::Element => Role::ElementNone,
                };
                match tok {
                    Tok::Space => (none, keep),
                    Tok::DeclClose => (none, Some(self.subset_state())),
                    _ => (Role::Error, None),
                }
            }
            S::Failed => (Role::None, keep),
        }
    }

    /// Tokens between declarations, shared by both kinds of subset.
    fn between_declarations(&self, tok: Tok, text: &[u8]) -> (Role, Option<State>) {
        let keep = Some(self.state);
        match tok {
            Tok::Space | Tok::Empty => (Role::None, keep),
            Tok::DeclOpen => match text {
                b"ENTITY" => (Role::EntityNone, Some(State::EntityKeyword)),
                b"ATTLIST" => (Role::AttlistNone, Some(State::AttlistKeyword)),
                b"ELEMENT" => (Role::ElementNone, Some(State::ElementKeyword)),
                b"NOTATION" => (Role::NotationNone, Some(State::NotationKeyword)),
                _ => (Role::Error, None),
            },
            Tok::Pi => (Role::Pi, keep),
            Tok::Comment => (Role::Comment, keep),
            Tok::ParamEntityRef => (Role::ParamEntityRef, keep),
            Tok::CloseBracket if self.state == State::InternalSubset => (Role::DoctypeNone, Some(State::DoctypeAfterSubset)),
            _ => (Role::Error, None),
        }
    }

    /// Where a finished declaration returns to.
    fn subset_state(&self) -> State {
        if self.document_entity { State::InternalSubset } else { State::ExternalSubset }
    }
}

/// The occurrence of a content particle named by `tok`.
fn particle(tok: Tok) -> Option<Quant> {
    match tok {
        Tok::Name | Tok::PrefixedName => Some(Quant::One),
        Tok::NameQuestion => Some(Quant::Opt),
        Tok::NameAsterisk => Some(Quant::Rep),
        Tok::NamePlus => Some(Quant::Plus),
        _ => None,
    }
}
