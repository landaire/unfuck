import copy
import copy_reg
import types


class Point(object):
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __eq__(self, other):
        return type(self) is type(other) and vars(self) == vars(other)


class Slotted(object):
    __slots__ = ('a', 'b')


class Stateful(object):
    def __init__(self):
        self.items = [1, [2, 3]]

    def __getstate__(self):
        return {'items': self.items, 'copied': True}


class Listed(list):
    pass


class Mapped(dict):
    pass


point = Point(1, [2])
shallow = copy.copy(point)
deep = copy.deepcopy(point)

slotted = Slotted()
slotted.a = 1
slotted_copy = copy.copy(slotted)

stateful_copy = copy.deepcopy(Stateful())

listed = Listed([1, 2])
listed.tag = 'list'
listed_copy = copy.deepcopy(listed)

mapped = Mapped(a=1)
mapped_copy = copy.copy(mapped)

reduced = point.__reduce_ex__(2)
legacy = point.__reduce_ex__(1)

RESULT = (
    shallow == point,
    shallow.y is point.y,
    deep.y is point.y,
    deep == point,
    (slotted_copy.a, hasattr(slotted_copy, 'b')),
    Slotted.__slotnames__,
    vars(stateful_copy),
    (type(listed_copy).__name__, list(listed_copy), listed_copy.tag),
    (type(mapped_copy).__name__, dict(mapped_copy)),
    (reduced[0] is copy_reg.__newobj__, reduced[1][0] is Point, reduced[2], reduced[3], reduced[4]),
    (legacy[0] is copy_reg._reconstructor, legacy[1], legacy[2]),
    set([1, 2]).__reduce__(),
    types.FunctionType.__name__,
    types.GetSetDescriptorType.__name__,
    types.MemberDescriptorType.__name__,
)
