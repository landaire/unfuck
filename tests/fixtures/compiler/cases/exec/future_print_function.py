from __future__ import print_function
import sys

print('a', 'b', sep=',', end='\n', file=sys.stderr)
print()
p = print

def inner(*args):
    print(*args)
