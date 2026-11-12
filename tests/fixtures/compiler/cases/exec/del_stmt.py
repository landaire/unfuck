a = b = c = 1
obj = type('Obj', (), {})()
obj.attribute = 1
items = [1, 2, 3, 4]
del a
del b, c
del obj.attribute
del items[0]
del items[1:2]
del items[:]
del items[::2]
del (items[0], [items[0]])

def in_function(x, y):
    z = 1
    del x
    del y, z
    def inner():
        return w
    w = 1
    del inner
