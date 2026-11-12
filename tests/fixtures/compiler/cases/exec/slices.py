x = range(10)
a = x[:]
b = x[1:]
c = x[:2]
d = x[1:2]
e = x[::2]
f = x[1:2:3]
g = x[::]
h = x[...]
i = x[1:2, 3]
j = x[..., 1:2:3]
k = x[1,]
l = x[:, :]
x[1:2] = [5]
x[:] = []
x[::2] = []
x[1, 2] = 3
x[...] = 0
m = x[-1]
n = x[1:2][0]

def in_function(seq, lo, hi):
    seq[lo:hi] = seq[hi:lo]
    return seq[lo:], seq[:hi], seq[lo:hi:-1]
