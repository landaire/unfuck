//! Declarations collected from the DTD, shared by a document parser and the
//! parsers it creates for external entities.

use std::collections::HashMap;
use std::rc::Rc;

/// The parameter entity that stands for the external DTD subset.
pub(super) const EXTERNAL_SUBSET: &[u8] = b"#";

/// A general or parameter entity.
#[derive(Clone, Debug, Default)]
pub(super) struct Entity {
    /// Replacement text in UTF-8 for an internal entity.
    pub text: Option<Rc<[u8]>>,
    pub system_id: Option<Rc<[u8]>>,
    pub public_id: Option<Rc<[u8]>>,
    pub base: Option<Rc<[u8]>>,
    /// The notation of an unparsed entity.
    pub notation: Option<Rc<[u8]>>,
    /// Declared by the document entity itself, outside any parameter entity.
    pub is_internal: bool,
    /// Being expanded right now; referring to it again is recursion.
    pub open: bool,
}

/// An attribute declared for an element type.
#[derive(Clone, Debug)]
pub(super) struct DeclaredAttribute {
    pub name: Rc<[u8]>,
    /// The normalized default; `None` for #IMPLIED and #REQUIRED.
    pub value: Option<Rc<[u8]>>,
    pub is_cdata: bool,
}

/// The attribute declarations of one element type, in declaration order.
#[derive(Clone, Debug, Default)]
pub(super) struct ElementType {
    pub attributes: Vec<DeclaredAttribute>,
    /// The first attribute declared with type ID.
    pub id_attribute: Option<Rc<[u8]>>,
}

impl ElementType {
    /// Records an attribute declaration. A declaration with a default or of
    /// type ID that repeats an attribute already listed is ignored.
    pub(super) fn declare(&mut self, attribute: DeclaredAttribute, is_id: bool, ns_reserved: bool) {
        if attribute.value.is_some() || is_id {
            if self.attributes.iter().any(|known| known.name == attribute.name) {
                return;
            }
            if is_id && self.id_attribute.is_none() && !ns_reserved {
                self.id_attribute = Some(Rc::clone(&attribute.name));
            }
        }

        self.attributes.push(attribute);
    }

    /// Whether values of the attribute `name` are left as CDATA.
    pub(super) fn is_cdata(&self, name: &[u8]) -> bool {
        self.attributes.iter().find(|known| &*known.name == name).is_none_or(|known| known.is_cdata)
    }
}

/// The declarations and document-wide flags.
#[derive(Debug, Default)]
pub(super) struct Dtd {
    pub general: HashMap<Rc<[u8]>, Entity>,
    pub parameter: HashMap<Rc<[u8]>, Entity>,
    pub elements: HashMap<Rc<[u8]>, Rc<ElementType>>,

    /// The document declared `standalone="yes"`.
    pub standalone: bool,
    /// A parameter entity reference or an external subset occurred.
    pub has_param_entity_refs: bool,
    /// Declarations are still processed: no parameter entity was skipped
    /// in a document that is not standalone.
    pub keep_processing: bool,
    /// An external parameter entity parser read its entity.
    pub param_entity_read: bool,

    /// The replacement text of the entity value being read, which external
    /// parameter entity parsers append to.
    pub entity_value: Vec<u8>,
}

impl Dtd {
    pub(super) fn new() -> Self {
        Self { keep_processing: true, ..Default::default() }
    }

    pub(super) fn entities(&self, parameter: bool) -> &HashMap<Rc<[u8]>, Entity> {
        if parameter { &self.parameter } else { &self.general }
    }

    pub(super) fn entities_mut(&mut self, parameter: bool) -> &mut HashMap<Rc<[u8]>, Entity> {
        if parameter { &mut self.parameter } else { &mut self.general }
    }

    /// The element type `name` for adding declarations, created on first use.
    pub(super) fn element_mut(&mut self, name: &[u8]) -> &mut ElementType {
        Rc::make_mut(self.elements.entry(Rc::from(name)).or_default())
    }

    /// The declarations of element type `name`, if it has any.
    pub(super) fn element(&self, name: &[u8]) -> Option<Rc<ElementType>> {
        self.elements.get(name).cloned()
    }
}
