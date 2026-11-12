rows = []
b = bytearray()
for i in range(120):
    b.append(65)
    rows.append(b.__alloc__())
for i in range(120):
    b.pop()
    rows.append(b.__alloc__())
for n in (0, 1, 2, 9, 17):
    rows.append((bytearray(n).__alloc__(), bytearray([1] * n).__alloc__(), bytearray(memoryview('z' * n)).__alloc__(), bytearray(buffer('w' * n)).__alloc__()))
for start in (0, 3, 9, 40):
    for k in (0, 1, 8, 33):
        b = bytearray('a' * start)
        b.extend('b' * k)
        c = bytearray('a' * start)
        c += 'c' * k
        d = bytearray('a' * start)
        d *= k
        e = bytearray('a' * start)
        del e[:k]
        rows.append((b.__alloc__(), c.__alloc__(), d.__alloc__(), e.__alloc__(), e.__sizeof__()))
RESULT = rows
