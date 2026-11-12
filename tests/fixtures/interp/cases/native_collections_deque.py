from _collections import deque


def error(action):
    try:
        action()
    except Exception as e:
        return repr(e)


d = deque([1, 2, 3])
d.append(4)
d.appendleft(0)
popped = (d.pop(), d.popleft())
d.extend([5, 6])
d.extendleft([-1, -2])
items = [x for x in d]
d.rotate(2)
rotated = [x for x in d]
d.rotate(-3)
rotated_back = [x for x in d]
d.remove(5)
counts = (d.count(1), d.count(42))
indexed = (d[0], d[-1], len(d))
d[1] = 'x'
del d[0]
after_set = [x for x in d]

bounded = deque('abcdef', 3)
bounded.append('g')
bounded.appendleft('z')
empty_bound = deque(maxlen=0)
empty_bound.append(1)

errors = [error(action) for action in (
    lambda: deque().pop(),
    lambda: deque().popleft(),
    lambda: d.remove(99),
    lambda: d[100],
    lambda: d['a'],
    lambda: deque([], -1),
    lambda: deque([], 'a'),
    lambda: d.rotate(1.5),
    lambda: hash(d),
    lambda: deque(1, 2, 3),
    lambda: deque(5),
)]

mutated = deque([1, 2, 3])


def mutate():
    for item in mutated:
        mutated.append(item)


mutation = error(mutate)
reversed_items = [x for x in deque([1, 2, 3]).__reversed__()]
comparisons = (deque([1, 2]) == deque([1, 2]), deque([1, 2]) < deque([1, 3]), deque([1]) != deque([1]),
               deque([1, 2]) > deque([1]), deque([1]) == [1])
grown = deque([1, 2])
grown += [3]
grown.extend(grown)
self_reference = deque([1])
self_reference.append(self_reference)
grown.extendleft('ab')


class Queue(deque):
    def __init__(self, items, maxlen=4):
        deque.__init__(self, items, maxlen)
        self.label = 'queue'


queue = Queue([1, 2, 3, 4, 5])
queue_copy = queue.__copy__()

RESULT = (popped, items, rotated, rotated_back, counts, indexed, after_set, repr(bounded), bounded.maxlen,
          repr(empty_bound), errors, mutation, reversed_items, comparisons, repr(grown), repr(self_reference),
          d.maxlen, 3 in grown, 9 in grown, not deque(), not grown, repr(deque([1], 2.7)),
          deque([1, 2]).__reduce__(), deque([1], 3).__reduce__(), repr(deque([5], 4).__copy__()),
          repr(queue), queue.label, type(queue_copy).__name__, repr(queue_copy), deque.__module__,
          type(iter(deque())).__name__, type(deque().__reversed__()).__name__)
