import weakref

log = []


class Node(object):
    def __init__(self, name, child=None):
        self.name = name
        self.child = child

    def __del__(self):
        log.append('del ' + self.name)


class Box(list):
    def __del__(self):
        log.append('del box %d' % len(self))


class Late(object):
    def __del__(self):
        log.append('late del')
        Late.ref = weakref.ref(self, lambda reference: log.append('never called'))


outer = Node('outer', Node('middle', Node('inner')))
del outer
log.append('chain done')

container = [Node('first'), Node('second'), Node('third')]
del container
log.append('list done')

mapping = {1: Node('one'), 2: Node('two')}
mapping = None
log.append('dict done')

box = Box([1, 2, 3])
box = 5
log.append('box done')

late = Late()
log.append(('weakrefs before', weakref.getweakrefcount(late)))
del late
log.append(('late ref', Late.ref()))


def func():
    pass


func_ref = weakref.ref(func, lambda reference: log.append('function gone'))
del func
log.append('function done')


class Temporary(object):
    pass


class_ref = weakref.ref(Temporary, lambda reference: log.append('class gone'))
log.append(class_ref() is Temporary)


def generator_owner():
    node = Node('generator local')
    yield 1
    yield 2


gen = generator_owner()
next(gen)
del gen
log.append('generator done')


def reraise():
    node = Node('finally local')
    try:
        raise ValueError('x')
    finally:
        log.append('finally')
        del node


try:
    reraise()
except ValueError:
    log.append('handled')
log.append('after reraise')

pairs = [(Node('tuple a'), Node('tuple b'))]
pairs.pop()
log.append('tuple done')

log.append('end')
RESULT = log
