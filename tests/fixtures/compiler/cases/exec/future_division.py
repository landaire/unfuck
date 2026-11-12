"""Docstring before the future import."""
from __future__ import division

a = 7 / 2
b = 7 // 2
c = 1 / 2
a /= 2
a //= 2

def inner(x, y):
    x /= y
    return x / y, 3 / 2
