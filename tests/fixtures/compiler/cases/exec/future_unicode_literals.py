from __future__ import (unicode_literals,
                        print_function)

text = 'text'
raw = r'raw\n'
explicit_bytes = b'bytes'
escaped = '\xe9\u1234'
empty = ''
single = 'a'
mixed = 'a' 'b'

def inner():
    "Unicode docstring."
    return 'abc', b'abc'
