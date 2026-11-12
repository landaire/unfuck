class Sub(dict):
    def __setitem__(self, key, value):
        dict.__setitem__(self, key, (value, 'via setitem'))

source = {}
for k in range(40):
    source[k * 8] = k
for k in range(0, 40, 3):
    del source[k * 8]
# The presize reads the source's fill, which counts deleted slots.
from_dict = dict.fromkeys(source)
from_set = dict.fromkeys(set([5, 13, 21, 3, 11]), 'v')
from_frozenset = dict.fromkeys(frozenset(['x', 'y', 'z']))
from_list = dict.fromkeys([24, 16, 8, 0], [])
from_string = dict.fromkeys('hello')
sub = Sub.fromkeys([1, 2])
via_instance = {}.fromkeys((3, 4), 7)
small_dict = dict.fromkeys({32: 1, 0: 2, 64: 3})

RESULT = (from_dict.keys(), from_set, from_frozenset, from_list, from_string, sub, type(sub).__name__, via_instance, small_dict.keys())
