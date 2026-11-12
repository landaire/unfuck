s = set()
for k in (8, 16, 24, 1, 9, 2):
    s.add(k)
inserted = list(s)
s.discard(16)
s.remove(1)
s.add(32)
s.add(1)
after = list(s)
popped = []
p = set([40, 8, 16, 24, 3])
while p:
    popped.append(p.pop())
from_list = list(set([33, 1, 65, 17, 9, 97]))
from_dict = list(set({33: 0, 1: 0, 65: 0, 17: 0}))
from_set = list(set(set([33, 1, 65, 17])))
from_string = sorted(set('mississippi'))
big = set(range(0, 200, 7))
for k in range(0, 200, 14):
    big.discard(k)
big_order = list(big)
literal = list({8, 16, 0, 24})
words = list(set(['spam', 'eggs', 'ham', 'bacon', 'toast']))

RESULT = (inserted, after, popped, from_list, from_dict, from_set, from_string, big_order, literal, words)
