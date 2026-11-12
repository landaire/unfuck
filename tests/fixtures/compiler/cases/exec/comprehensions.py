data = range(5)
squares = [x * x for x in data]
pairs = [(x, y) for x in data if x for y in data if y > x]
matrix = [[x * y for y in data] for x in data]
unique = {x % 3 for x in data}
mapping = {x: x * x for x in data if x}
nested_set = {(a, b) for a in data for b in data}
nested_dict = {k: {v: k for v in data} for k in data}
tuple_target = [a + b for a, b in zip(data, data)]

def in_function(items, offset):
    local = [item + offset for item in items]
    setc = {item for item in items if item != offset}
    dictc = {item: offset for item in items}
    return local, setc, dictc

def leaks_variable(items):
    [leaked for leaked in items]
    return leaked
