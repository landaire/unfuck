import gc

log = []


class Tracked(object):
    def __init__(self, name):
        self.name = name

    def __del__(self):
        log.append('del ' + self.name)


class Classic:
    def __init__(self, name):
        self.name = name

    def __del__(self):
        log.append('classic del ' + self.name)


def scope():
    local = Tracked('local')
    log.append('in scope')
    return 1


a = Tracked('a')
log.append('before del')
del a
log.append('after del')

scope()
log.append('after scope')

b = Tracked('b1')
b = Tracked('b2')
log.append('after rebind')

d = {'k': Tracked('d1')}
d['k'] = Tracked('d2')
log.append('after overwrite')
d.clear()
log.append('after clear')

c = Classic('c')
c = None
log.append('after classic')

items = [Tracked('p1'), Tracked('p2')]
items.pop()
log.append('after pop')
items.pop(0)
log.append('after pop0')


class Context(object):
    def __enter__(self):
        return Tracked('with')

    def __exit__(self, *args):
        log.append('exit')


with Context() as w:
    log.append('in with')
del w
log.append('after with')

saved = []


class Phoenix(object):
    count = 0

    def __del__(self):
        Phoenix.count += 1
        log.append('phoenix %d' % Phoenix.count)
        if Phoenix.count == 1:
            saved.append(self)


p = Phoenix()
del p
log.append('resurrected %d' % len(saved))
saved.pop()
log.append('after second death')


class Failing(object):
    def __del__(self):
        log.append('failing del')
        raise ValueError('ignored')


f = Failing()
del f
log.append('after failing')


def handler():
    held = Tracked('handler local')
    try:
        raise KeyError('k')
    except KeyError:
        log.append('caught')
    del held
    log.append('after handler')


handler()

# The count includes garbage the generator's other cases left behind.
gc.collect()
log.append('collected')
log.append([Tracked('temp')] and 'temp expression')
log.append('end')
RESULT = log
