with open('a') as f:
    f.read()

with open('b'):
    pass

with open('c') as (first, second):
    pass

with open('d') as f, open('e') as g:
    g.write(f.read())

def in_function(lock, items):
    with lock:
        with lock as held:
            for item in items:
                if item:
                    return held
    with lock as self.attribute:
        pass
