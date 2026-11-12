empty_list = []
empty_tuple = ()
empty_dict = {}
one_tuple = 1,
items = [1, 'a', None]
variable = 3
mixed_tuple = (1, variable, 2)
pairs = {1: 2, 'a': variable, variable: [3]}
a_set = {1, 2, variable}
single_set = {1}
nested = [[], [[]], ((),)]
first, second = 1, 2
first, (second, third) = 1, (2, 3)
[fourth, fifth] = [4, 5]
first, second = second, first
first, second, third = third, second, first
x = y = z = 0
x, y = z, w = 1, 2
items[0], items[1] = items[1], items[0]

def in_function(a, b):
    a, b = b, a
    a, b, c = b, a, a
    return [a, b], {a: b}, {a, b}, (a, b), ()
