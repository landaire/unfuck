empty = ''
dot = '.'
newline = '\n'
letter = 'a'
escaped_letter = '\x61'
name_like = 'name_like'
not_name_like = 'not name-like'
two = 'ab'
raw = r'\n'
high = '\xff'
nul = 'a\0b'
nul_name = 'abc\0'
concatenated = 'a' 'b'
concat_empty = '' 'c'
triple = '''multi
line'''
tuple_of_strings = ('.', '\n', 'ab', 'a b', '')
nested = ('x', ('y', ('name', 'na me')))
same_twice = ('repeat', 'repeat', 'name_like')
dictionary = {'key': 'value', 'k e y': 'v'}

def uses(a):
    return a + '.' + '\n' + 'name_like' + 'two words', ('in', 'tuple')
