data = range(10)
squares = (x * x for x in data)
filtered = (x for x in data if x % 2 if x > 3)
nested = ((x, y) for x in data for y in range(x) if y)
total = sum(x for x in data)
call_args = sorted((x for x in data), reverse=True)

def in_function(items, factor):
    return list(item * factor for item in items)

def nested_genexp(rows):
    return (sum(cell for cell in row) for row in rows)

class InClass:
    values = [1, 2]
    doubled = tuple(v * 2 for v in values)
