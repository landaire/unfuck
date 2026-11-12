log = []


class T(object):
    def __init__(self, name):
        self.name = name

    def __del__(self):
        log.append('del ' + self.name)


class Getter(object):
    def __get__(self, instance, owner):
        log.append('get')
        raise ValueError('lookup failure')


class Odd(object):
    __del__ = Getter()


o = Odd()
del o
log.append('after descriptor')


def paused():
    local = T('generator local')
    try:
        yield 1
        yield 2
    finally:
        log.append('generator finally')


g = paused()
next(g)
del g
log.append('after generator')

fresh = paused()
del fresh
log.append('after fresh generator')


class Items(list):
    pass


x = Items([T('item')])
x.attr = T('dict')
del x
log.append('after list subclass')


class Link(object):
    count = 0

    def __init__(self, following):
        self.following = following

    def __del__(self):
        Link.count += 1


head = None
for index in range(20):
    head = Link(head)
del head
log.append(Link.count)
log.append('end')
RESULT = log
