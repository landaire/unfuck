import copy
import _elementtree as m
from xml.etree import cElementTree as cET


def K(value):
    return value


def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, str(e))


def tags(element):
    return [getattr(child, 'tag', child) for child in element]


E = m.Element
e = E(K('a'), {K('x'): K('1')}, y=K('2'))
T = type(e)
types = (T.__name__, T.__module__, repr(T), type(m.TreeBuilder()).__name__, type(m.XMLParser()).__name__)
creation = (err(T, K('x')), err(type, K('S'), (T,), {}), err(E), err(E, K('a'), [1]), err(E, K('a'), {}, {}), err(m.SubElement, 1, K('a')))
attributes = (e.tag, e.text, e.tail, sorted(e.attrib.items()), e.get(K('x')), e.get(K('z'), K('d')), sorted(e.keys()), sorted(e.items()))
lookups = tuple(err(getattr, e, K(name))[0] for name in ['__class__', '__dict__', '__doc__', '__repr__', '__len__', '__getitem__', '__reduce_ex__', 'foo'])
methods = (e.__methods__, dir(e), e.find.__name__, e.find.__self__ is e, type(e.find).__name__, getattr(e, K('getiterator')).__name__)
plain = E(K('p'))
empty = (plain[::K(0)], plain.keys(), plain.items(), plain.get(K('q')), len(plain), bool(plain), plain.getchildren(), plain[:], plain.attrib, err(lambda: plain[::K(0)]))


def assign(name, value):
    target = E(K('s'))
    try:
        setattr(target, name, value)
    except Exception as ex:
        return (type(ex).__name__, str(ex))
    return (target.tag, target.text, target.tail, target.attrib)


def delete(name):
    try:
        delattr(E(K('d')), name)
    except Exception as ex:
        return (type(ex).__name__, str(ex))


setting = (assign(K('tag'), 5), assign(K('text'), [1]), assign(K('tail'), K('t')), assign(K('attrib'), 3), assign(K('foo'), 1), delete(K('tag')), delete(K('foo')))
odd = E(K('o'))
odd.attrib = 3
odd_attrib = (odd.get(K('x'), K('d')), odd.attrib)
unhashable = (err(E(K('a'), {K('k'): 1}).get, []), err(E(K('a')).set, [], 1))

root = E(K('root'))
first = m.SubElement(root, K('first'), {K('n'): K('1')})
m.SubElement(root, K('second')).text = K('two')
third = E(K('third'))
root.append(third)
root.insert(K(0), E(K('zero')))
root.insert(K(-1), E(K('before-last')))
root.insert(K(-100), E(K('head')))
root.insert(K(100), E(K('tail')))
root.extend((E(K('x1')), E(K('x2'))))
structure = (tags(root), len(root), root[0].tag, root[-1].tag, [c.tag for c in root[1:4]], [c.tag for c in root[::-3]])
argument_errors = (
    err(root.append, 1),
    err(root.insert, 1.5, E(K('b'))),
    err(root.insert, K('x'), E(K('b'))),
    err(root.insert, 0, 1),
    err(root.remove, E(K('nope'))),
    err(root.extend, 5),
    err(root.find),
    err(root.find, K('a'), None, 3),
    err(root.find, tag=K('a')),
    err(root.clear, 1),
    # getiterator() parses its arguments as "iter".
    err(root.iter, 1, 2), err(root.getiterator, 1, 2),
    err(root.itertext, 1),
    err(root.makeelement, K('t')),
)
index_errors = (err(lambda: root[K(100)]), err(lambda: root[K('x')]), err(lambda: root[1.5]), err(lambda: root[2 ** 70]), err(lambda: root[::0]), err(lambda: E(K('a'))[0]))


class Index(object):
    def __index__(self):
        return 1


indexed = root[Index()].tag
root.remove(first)
after_remove = tags(root)


def item_assignment():
    target = E(K('r'))
    target.extend([E(str(i)) for i in range(5)])
    target[0] = 1
    target[-1] = E(K('last'))
    del target[1]
    return tags(target)


def slice_assignment(index, value):
    target = E(K('r'))
    target.extend([E(str(i)) for i in range(5)])
    try:
        if value is None:
            del target[index]
        else:
            target[index] = value
    except Exception as ex:
        return (type(ex).__name__, str(ex))
    return tags(target)


slices = (
    item_assignment(),
    err(lambda: E(K('a')).__setitem__(0, 1)),
    slice_assignment(slice(1, 3), [E(K('A')), E(K('B')), E(K('C'))]),
    slice_assignment(slice(1, 4), K('ab')),
    slice_assignment(slice(None, None, -2), [1, 2, 3]),
    slice_assignment(slice(None, None, 2), [1, 2]),
    slice_assignment(slice(0, 2), 5),
    slice_assignment(slice(1, 3), None),
    slice_assignment(slice(None, None, -1), None),
    slice_assignment(slice(None, None, 2), None),
    slice_assignment(slice(2, 2), (E(K('I')),)),
    slice_assignment(slice(10, 20), [E(K('Z'))]),
)

tree = cET.XML(K('<r><a id="1">x<b>y</b>z</a><c/><a>w</a></r>'))
finders = (
    tree.find(K('a')).get(K('id')),
    tree.findtext(K('a')),
    tree.findtext(K('c')),
    tree.findtext(K('missing'), K('dflt')),
    [x.tag for x in tree.findall(K('a'))],
    [x.tag for x in tree.findall(K('.//b'))],
    [x.tag for x in tree.iterfind(K('a/b'))],
    tree.find(K('{urn}a')),
    tree.find(K('a/b')).text,
    [x.tag for x in tree.iter()],
    [x.tag for x in tree.iter(K('a'))],
    [x.tag for x in tree.getiterator(K('*'))],
    list(tree.itertext()),
    list(tree[0].itertext()),
)

clear_target = E(K('c'), {K('a'): K('b')})
clear_target.text = K('t')
clear_target.tail = K('u')
clear_target.append(E(K('x')))
clear_target.clear()
cleared = (clear_target.tag, clear_target.text, clear_target.tail, clear_target.attrib, len(clear_target))

source = E(K('src'), {K('k'): K('v')})
source.text = K('text')
source.append(E(K('child')))
shallow = source.__copy__()
deep = copy.deepcopy(source)
via_copy = copy.copy(source)
reduced = source.__reduce__()
made = source.makeelement(K('made'), {K('m'): 1})
copies = (
    shallow.tag, shallow.text, shallow.attrib is source.attrib, shallow[0] is source[0],
    deep.tag, deep.text, deep.attrib == source.attrib, deep.attrib is source.attrib, deep[0] is source[0], deep[0].tag,
    via_copy is source, via_copy.attrib is source.attrib,
    reduced[0].__name__, reduced[1][0].tag,
    made.tag, made.attrib, made.attrib is source.attrib,
)

reprs = (repr(E(K('a')))[:13], repr(E(u'\xe9'))[:16], repr(E(1))[:12], str(E(K('s')))[:12])
elementtree_module = (cET.VERSION, m.__version__, cET.iselement(e), cET.iselement(1), sorted(k for k in dir(m) if not k.startswith('__')))

RESULT = (types, creation, attributes, lookups, methods, empty, setting, odd_attrib, unhashable, structure, argument_errors, index_errors, indexed, after_remove, slices, finders, cleared, copies, reprs, elementtree_module)
