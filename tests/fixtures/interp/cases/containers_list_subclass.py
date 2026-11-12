class Stack(list):
    def __init__(self, items=()):
        list.__init__(self, items)
        self.pushes = 0
    def append(self, item):
        self.pushes += 1
        list.append(self, item)
    def __getitem__(self, index):
        return ('item', list.__getitem__(self, index))
    def __setitem__(self, index, value):
        list.__setitem__(self, index, value * 2)
    def __len__(self):
        return list.__len__(self) + 100

s = Stack([1, 2])
s.append(3)
s[0] = 5
s.extend([4])
plain = list(s)
r = (s[0], s[1:3], s.pushes, len(s), list.__len__(s), repr(s), s == [5, 2, 3, 4], isinstance(s, list), type(s + [1]).__name__, sorted(s))

class Empty(list):
    pass

e = Empty()
e += [1, 2]
e2 = Empty('ab')

RESULT = (plain, r, e, type(e).__name__, e2, bool(Empty()))
