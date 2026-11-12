import weakref

log = []


class Target(object):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return 'Target(%s)' % self.name


class Finalized(object):
    def __del__(self):
        log.append('del finalized')


t = Target('t')
basic = weakref.ref(t)
callback_refs = []


def callback(reference):
    log.append(('callback', reference is first, reference(), reference in callback_refs))


first = weakref.ref(t, callback)
second = weakref.ref(t, lambda reference: log.append('second callback'))
callback_refs.append(first)
proxy = weakref.proxy(t)
log.append((basic() is t, weakref.getweakrefcount(t), weakref.getweakrefs(t)[0] is basic, proxy.name, basic is weakref.ref(t)))
del t
log.append(('after del', basic(), first(), weakref.getweakrefcount(basic)))
try:
    proxy.name
except ReferenceError as e:
    log.append(('proxy', str(e)))
log.append(repr(basic).endswith('; dead>'))
try:
    hash(first)
except TypeError as e:
    log.append(('hash', str(e)))
log.append((basic == basic, basic == first, basic != first))

f = Finalized()
fr = weakref.ref(f, lambda reference: log.append('finalized callback'))
del f
log.append(('finalized gone', fr()))

values = weakref.WeakValueDictionary()
keep = Target('keep')
values['keep'] = keep
values['drop'] = Target('drop')
log.append(sorted(values.keys()))
temporary = Target('temp')
values['temp'] = temporary
log.append(len(values))
del temporary
log.append((len(values), sorted(values.keys())))

keys = weakref.WeakKeyDictionary()
k1 = Target('k1')
k2 = Target('k2')
keys[k1] = 1
keys[k2] = 2
del k1
log.append(sorted(key.name for key in keys.keys()))

members = weakref.WeakSet()
m1 = Target('m1')
m2 = Target('m2')
members.add(m1)
members.add(m2)
del m2
log.append((len(members), [member.name for member in members]))


def failing(reference):
    raise RuntimeError('callback failure')


g = Target('g')
gr = weakref.ref(g, failing)
del g
log.append(('after failing callback', gr()))

order = Target('order')
refs = [weakref.ref(order, lambda reference, index=index: log.append(('order', index))) for index in range(3)]
del order
log.append('end')
RESULT = log
