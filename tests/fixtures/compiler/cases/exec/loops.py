for i in range(3):
    if i == 1:
        continue
    if i == 2:
        break
else:
    i = None

while i:
    i -= 1
    if i:
        break
else:
    i = 0

for a, (b, c) in [(1, (2, 3))]:
    pass

def continue_in_try(items):
    for item in items:
        try:
            if item:
                continue
        except ValueError:
            continue
        finally:
            pass
    return item

def nested_loops(n):
    while n:
        for k in range(n):
            if k:
                break
            continue
        else:
            n -= 1
            continue
        return k

def infinite():
    while 1:
        pass

def infinite_true():
    while True:
        break

def never():
    while 0:
        pass
    else:
        return 1

def for_attribute_target(obj, items):
    for obj.attribute in items:
        pass
    for obj[0] in items:
        pass
