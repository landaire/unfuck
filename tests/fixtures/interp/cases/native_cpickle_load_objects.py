import cPickle
import imp
import sys
import copy_reg
import re


# Pickles name globals of this module; the reference runs cases outside
# sys.modules, so they are published under a registered module.
HOST = imp.new_module('cpickle_load_host')
sys.modules['cpickle_load_host'] = HOST


def K(x):
    return x


def failure(data):
    try:
        cPickle.loads(K(data))
    except Exception as e:
        return (type(e).__name__, re.sub('0x[0-9A-Fa-f]+', '0x...', str(e)))
    return 'no error'


LOG = []


class Classic:
    def __init__(self, *args):
        LOG.append(('Classic.__init__', args))
        self.args = args


class ClassicNoInit:
    pass


class ClassicInitArgs:
    def __getinitargs__(self):
        return ()

    def __init__(self):
        LOG.append('ClassicInitArgs.__init__')
        self.made = True


class ClassicSetState:
    def __setstate__(self, state):
        LOG.append(('ClassicSetState.__setstate__', state))
        self.state = state


class NewStyle(object):
    def __init__(self, *args):
        LOG.append(('NewStyle.__init__', args))
        self.args = args


class NewArgs(object):
    def __new__(cls, *args):
        LOG.append(('NewArgs.__new__', args))
        self = object.__new__(cls)
        self.new_args = args
        return self


class Slotted(object):
    __slots__ = ('a', 'b')


class SlottedDict(object):
    __slots__ = ('a', '__dict__')


class Raising(object):
    def __init__(self, value):
        raise ValueError('bad value %r' % (value,))


class ClassicRaising:
    def __init__(self, value):
        raise KeyError(value)


def make(*args):
    LOG.append(('make', args))
    return list(args)


for _name in ['Classic', 'ClassicNoInit', 'ClassicInitArgs', 'ClassicSetState', 'NewStyle', 'NewArgs', 'Slotted', 'SlottedDict', 'Raising', 'ClassicRaising', 'make']:
    setattr(HOST, _name, globals()[_name])


def describe(value):
    if isinstance(value, (Classic, ClassicNoInit, ClassicInitArgs, ClassicSetState, NewStyle, NewArgs)):
        return (value.__class__.__name__, sorted(value.__dict__.items()))
    if isinstance(value, SlottedDict):
        return ('SlottedDict', sorted(value.__dict__.items()), getattr(value, 'a', '<unset>'))
    if isinstance(value, Slotted):
        return ('Slotted', hasattr(value, '__dict__'), [(name, getattr(value, name, '<unset>')) for name in Slotted.__slots__])
    return value


def load(data):
    del LOG[:]
    value = cPickle.loads(K(data))
    return (describe(value), list(LOG))


RESULT = [
    # INST, OBJ, and REDUCE of classic classes.
    load('(I1\nI2\nicpickle_load_host\nClassic\n.'),
    load('(icpickle_load_host\nClassic\n.'),
    load('(icpickle_load_host\nClassicNoInit\n.'),
    load('(icpickle_load_host\nClassicInitArgs\n.'),
    load('(ccpickle_load_host\nClassic\nI1\no.'),
    load('(ccpickle_load_host\nClassic\no.'),
    load('(ccpickle_load_host\nClassicNoInit\no.'),
    load('ccpickle_load_host\nClassic\n(I3\ntR.'),
    load('ccpickle_load_host\nClassic\n)R.'),
    load('ccpickle_load_host\nClassicNoInit\n]R.'),
    load('ccpickle_load_host\nClassicInitArgs\n)R.'),
    # BUILD with a state dict, __setstate__, and slot state.
    load('(icpickle_load_host\nClassicNoInit\n(dS\'x\'\nI1\nsb.'),
    load('(icpickle_load_host\nClassicSetState\nI7\nb.'),
    load('(icpickle_load_host\nClassicNoInit\nN}U\x01yK\x02s\x86b.'),
    load('\x80\x02ccpickle_load_host\nNewStyle\n)\x81}U\x01aK\x01sb.'),
    load('\x80\x02ccpickle_load_host\nSlotted\n)\x81N}(U\x01aK\x01U\x01bK\x02u\x86b.'),
    load('\x80\x02ccpickle_load_host\nSlotted\n)\x81N}U\x01aK\x01s\x86b.'),
    load('\x80\x02ccpickle_load_host\nSlottedDict\n)\x81}U\x01xK\x05s}U\x01aK\x06s\x86b.'),
    load('\x80\x02ccpickle_load_host\nNewArgs\nK\x01K\x02\x86\x81.'),
    load('\x80\x02ccpickle_load_host\nNewStyle\nK\x01\x85R.'),
    load('ccpickle_load_host\nmake\n(I1\nS\'a\'\ntR.'),
    # NEWOBJ and REDUCE through copy_reg.
    load('ccopy_reg\n_reconstructor\n(ccpickle_load_host\nNewStyle\nc__builtin__\nobject\nNtR(dS\'z\'\nI3\nsb.'),
    load('\x80\x02ccopy_reg\n__newobj__\nccpickle_load_host\nNewArgs\nK\x09\x86R.'),
    # Failing constructors.
    failure('ccpickle_load_host\nRaising\n(K\x01tR.'),
    failure('ccpickle_load_host\nClassicRaising\n(K\x01tR.'),
    failure('ccpickle_load_host\nClassic\nK\x01R.'),
    failure('ccpickle_load_host\nNewStyle\nK\x01R.'),
    failure('ccpickle_load_host\nClassicNoInit\n(K\x01tR.'),
    failure('(K\x01icpickle_load_host\nClassicNoInit\n.'),
    failure('\x80\x02ccpickle_load_host\nClassic\n)\x81.'),
    failure('\x80\x02c__builtin__\nlen\n)\x81.'),
]

# Keys of a BUILD state dict are interned like attribute names.
built = cPickle.loads(K('(icpickle_load_host\nClassicNoInit\n(dS\'interned_attribute_name\'\nI1\nsb.'))
RESULT.append([key is 'interned_attribute_name' for key in built.__dict__])

# Memoized objects are shared.
shared = cPickle.loads(K('(lp0\n(lp1\nag1\na.'))
RESULT.append((shared, shared[0] is shared[1]))
cycle = cPickle.loads(K(']q\x00h\x00a.'))
RESULT.append(cycle[0] is cycle)

# Globals of modules not imported yet go through __import__.
RESULT.append(cPickle.loads(K('ckeyword\nkwlist\n.'))[:3])
RESULT.append(cPickle.loads(K('cencodings.ascii\nCodec\n.')).__name__)
