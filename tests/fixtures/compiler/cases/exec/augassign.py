x = 1
x += 1
x -= 1
x *= 2
x /= 2
x //= 2
x %= 3
x **= 2
x <<= 1
x >>= 1
x &= 7
x |= 8
x ^= 1

obj = type('Obj', (), {})()
obj.value = 1
obj.value += 1
items = [1, 2, 3]
items[0] += 1
items[1:2] += [4]
items[:] += []
items[:1] *= 2
items[1:] -= []
items[::2] += []
items[0, 1] += 1

def in_function(a, b):
    a += b
    a.b.c += 1
    a[b][0] += 1
    a[b:] += a
    return a

def closure(a):
    def inner():
        return a
    a += 1
    return inner
