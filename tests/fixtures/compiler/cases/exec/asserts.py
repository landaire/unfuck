x = 1
assert x
assert x, 'message'
assert x > 0, (x, 'tuple message')
assert (x, 'always true')
assert 1
assert 0, 'never'

def in_function(value):
    assert value is not None
    assert isinstance(value, int), value
    return value
