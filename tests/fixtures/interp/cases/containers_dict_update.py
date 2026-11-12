class Mapping(object):
    def __init__(self, pairs):
        self.pairs = pairs
        self.calls = []
    def keys(self):
        self.calls.append('keys')
        return [k for k, v in self.pairs]
    def __getitem__(self, key):
        self.calls.append(key)
        for k, v in self.pairs:
            if k == key:
                return v
        raise KeyError(key)

class Sub(dict):
    pass

base = {8: 'a', 16: 'b'}
from_dict = {24: 'c'}
from_dict.update(base)
from_pairs = {}
from_pairs.update([(16, 'x'), (8, 'y'), (16, 'z')])
from_kwargs = {}
from_kwargs.update(one=1, two=2, three=3)
both = dict([('a', 1)], b=2, a=3)
mapping = Mapping([('k1', 1), ('k2', 2)])
from_mapping = dict(mapping)
sub = Sub(x=1)
sub.update({'y': 2})
from_sub = dict(sub)
itself = {1: 2, 9: 3}
itself.update(itself)
tuples = dict(((i, i * i) for i in range(12)))
nested = dict(zip('abcdef', range(6)))
strings = dict(['ab', 'cd'])
big = {}
big.update(dict.fromkeys(range(20), 0))
big.update(dict.fromkeys(range(10, 30), 1))

RESULT = (from_dict, from_pairs, sorted(from_kwargs.items()), both, from_mapping, mapping.calls, from_sub, type(from_sub).__name__, itself, tuples.items(), nested, strings, big.items())
