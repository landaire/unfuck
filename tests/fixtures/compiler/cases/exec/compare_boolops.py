a, b, c, d = 1, 2, 3, 4
r1 = a < b
r2 = a < b < c
r3 = a < b <= c != d
r4 = a is b is not c
r5 = a in [b] not in [[c]]
r6 = a == b > c >= d < a <> b
r7 = a and b
r8 = a or b or c
r9 = a and b or c and not d
r10 = not a
r11 = not (a < b)
r12 = not a in b
r13 = not a is b

if a and b or c:
    pass
if not a or not b:
    pass
if a < b < c:
    pass
while a and (b or c):
    break

def conditions(x, y):
    if x and y:
        return 1
    elif x or y:
        return 2
    elif not x:
        return 3
    return x if x < y < 10 else y
