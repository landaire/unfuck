if 0:
    removed = 1
if 1:
    kept = 1
if 0:
    removed = 2
else:
    kept = 2
if not 0:
    kept = 3
if '':
    removed = 3
if 'x':
    kept = 4
if None:
    removed = 4
if __debug__:
    kept = 5
if 0.0:
    removed = 5
if ():
    removed = 6
if 0:
    def removed_function():
        yield 1
while 0:
    removed = 7
while 1:
    break
while 'loop':
    break
while True:
    break
x = 1 if 0 else 2
y = 0 and 1
z = 1 or 2

def constant_return():
    if 1:
        return 1
    return 2

def zero_branch(a):
    if 0:
        a()
    elif a:
        return a
