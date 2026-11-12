# Interning by setattr, class and function creation, keyword binding,
# and the native dicts, checked with marshal.dumps and identity.
import marshal, sys, binascii, types, string


def K(x):
    return x


def m(x):
    return marshal.dumps(x)[0]


def fresh(text):
    return binascii.unhexlify(binascii.hexlify(text))


def J(*parts):
    return ''.join(parts)


class O(object):
    pass


class Old:
    pass


class S(str):
    pass


def key_of(d, text):
    for k in d:
        if k == text:
            return k


R = []

o = O()
n = fresh('attr_one')
R.append(('fresh_before', m(n)))
setattr(o, n, 1)
R.append(('setattr_interns_arg', m(n), intern(n) is n, key_of(vars(o), 'attr_one') is n))

old = Old()
n = fresh('attr_two')
setattr(old, n, 1)
R.append(('old_setattr', m(n), key_of(vars(old), 'attr_two') is n))

n = fresh('attr_three')
getattr(o, n, None)
R.append(('getattr_no_intern', m(n)))
n = fresh('attr_three')
hasattr(o, n)
R.append(('hasattr_no_intern', m(n)))
o.attr_four = 1
n = fresh('attr_four')
delattr(o, n)
R.append(('delattr_interns', m(n), intern(n) is n))

n = fresh('attr_five')
existing = intern(fresh('attr_five'))
setattr(o, n, 1)
R.append(('setattr_existing', m(n), key_of(vars(o), 'attr_five') is existing, key_of(vars(o), 'attr_five') is n))


u = K(u'attr_seven')
setattr(o, u, 1)
R.append(('setattr_unicode', type(key_of(vars(o), 'attr_seven')).__name__, m(key_of(vars(o), 'attr_seven'))))

o.__dict__[fresh('attr_eight')] = 1
R.append(('dict_store', m(key_of(vars(o), 'attr_eight'))))

o2 = O()
o2.plain = 1
R.append(('store_attr', m(key_of(vars(o2), 'plain'))))

n = fresh('cls_name')
C = type(n, (object,), {})
R.append(('type_name', m(C.__name__), C.__name__ is n))
n = fresh('cls_old')
OC = types.ClassType(n, (), {})
R.append(('classobj_name', m(OC.__name__), OC.__name__ is n))
R.append(('class_stmt_name', m(O.__name__), m(Old.__name__)))

n = fresh('slot_a')
D = type('D', (object,), {'__slots__': (n,)})
R.append(('slots_arg', m(n), D.__slots__[0] is n, m(key_of(D.__dict__, 'slot_a')), key_of(D.__dict__, 'slot_a') is n))
n = fresh('slot_b')
D2 = type('D2', (object,), {'__slots__': n})
R.append(('slots_str', m(n), m(key_of(D2.__dict__, 'slot_b'))))

dk = fresh('dict_key')
d = type('E', (object,), {dk: 1}).__dict__
R.append(('type_dict_key', m(dk), key_of(d, 'dict_key') is dk))


def f():
    pass


R.append(('func_name', m(f.__name__), m(f.func_code.co_name)))
R.append(('lambda_name', m((lambda: 0).__name__)))
R.append(('genexpr_name', m((x for x in ()).gi_code.co_name)))
n = fresh('renamed')
f.__name__ = n
R.append(('func_rename', m(f.__name__), f.__name__ is n))


def kw(**kwargs):
    return kwargs


n = fresh('kw_name')
d = kw(**{n: 1})
R.append(('kwargs_key', m(key_of(d, 'kw_name')), key_of(d, 'kw_name') is n))
d = kw(kw_lit=1)
R.append(('kwargs_literal', m(key_of(d, 'kw_lit'))))
d = dict(dict_kw=1)
R.append(('dict_kw', m(key_of(d, 'dict_kw'))))
n = fresh('kw_bound')


def named(kw_bound=0):
    return kw_bound


named(**{n: 1})
R.append(('kw_bound', m(n)))

n = fresh('global_name')
globals()[n] = 1
R.append(('globals_store', m(key_of(globals(), 'global_name'))))
exec 'exec_name = 1'
R.append(('exec_name', m(key_of(globals(), 'exec_name'))))
ns = {}
exec fresh('exec_ns = 1') in ns
R.append(('exec_ns', m(key_of(ns, 'exec_ns'))))
code = compile(fresh('compiled_name + 1'), 'x', 'eval')
R.append(('compile_names', m(code.co_names[0]), m(code.co_filename)))
R.append(('marshal_t', m(marshal.loads(K('t\x03\x00\x00\x00xyz'))), intern(K('xy') + K('z')) is marshal.loads(K('t\x03\x00\x00\x00xyz'))))

R.append(('str_dict', m(key_of(str.__dict__, 'upper')), m(key_of(vars(binascii), 'hexlify')), m(key_of(vars(sys), 'maxint'))))
R.append(('int_dict', m(key_of(int.__dict__, '__add__')), m(key_of(int.__dict__, 'real'))))
R.append(('builtins_dict', m(key_of(vars(__builtins__) if isinstance(__builtins__, dict) is False else __builtins__, 'len'))))
R.append(('names', m(str.upper.__name__), m(len.__name__), m(type.__name__), m(int.__name__), m(binascii.__name__), m(K('').upper.__name__)))
R.append(('method_name', m(O.__init__.__name__), m(o.__init__.__name__), m(object.__new__.__name__)))
R.append(('module_attrs', m(key_of(vars(string), 'letters')), m(key_of(vars(string), '__name__'))))
R.append(('bool_str', m(str(K(True))), m(repr(K(False))), str(K(True)) is repr(K(True))))
R.append(('intern_ident', intern(K('a') + K('bc')) is intern(K('ab') + K('c')), intern(fresh('q')) is K('q')))
x = fresh('identity_check')
R.append(('intern_returns_existing', intern(x) is x, intern(fresh('identity_check')) is x))
try:
    intern(S('x'))
except TypeError as e:
    R.append(('intern_subclass', str(e)))
n = J('un', 'seen_a')
setattr(o, n, 1)
R.append(('setattr_unseen', m(n), intern(n) is n, key_of(vars(o), J('un', 'seen_a')) is n))
n = J('un', 'seen_b')
setattr(old, n, 1)
R.append(('old_setattr_unseen', m(n), key_of(vars(old), J('un', 'seen_b')) is n))
o.unseen_c = 1
n = J('unseen', '_c')
delattr(o, n)
R.append(('delattr_unseen', m(n)))
n = J('un', 'seen_d')
o.__dict__[n] = 1
getattr(o, n)
R.append(('getattr_unseen', m(n)))
n = J('un', 'seen_e')
C2 = type(n, (object,), {})
R.append(('type_name_unseen', m(n), m(C2.__name__)))
n = J('un', 'seen_f')
D3 = type('D3', (object,), {'__slots__': (n,)})
R.append(('slots_unseen', m(n), m(key_of(D3.__dict__, J('un', 'seen_f')))))
n = J('un', 'seen_g')
d = kw(**{n: 1})
R.append(('kwargs_unseen', m(n), key_of(d, J('un', 'seen_g')) is n))
n = J('un', 'seen_h')
globals()[n] = 1
R.append(('globals_unseen', m(n)))
n = J('un', 'seen_i')
setattr(O, n, 1)
R.append(('class_setattr_unseen', m(n), key_of(O.__dict__, J('un', 'seen_i')) is n))
n = J('un', 'seen_j')
setattr(string, n, 1)
R.append(('module_setattr_unseen', m(n), key_of(vars(string), J('un', 'seen_j')) is n))
n = J('un', 'seen_k')
setattr(Old, n, 1)
R.append(('classic_class_setattr_unseen', m(n)))
n = J('un', 'seen_l')
f.__dict__[n] = 1
setattr(f, J('un', 'seen_m'), 1)
R.append(('func_setattr_unseen', m(n), m(key_of(f.__dict__, J('un', 'seen_m')))))
R.append(('vars_keys', m(key_of(vars(o), '__dict__') or 'none')))
R.append(('dir_names', m([k for k in dir(o) if k == 'attr_one'][0]), m([k for k in dir(O) if k == '__init__'][0])))
R.append(('getattr_name_str', m(getattr(O, '__name__'))))
R.append(('mro_dict', m(key_of(O.__dict__, '__module__')), m(key_of(O.__dict__, '__dict__')), m(key_of(O.__dict__, '__doc__'))))
R.append(('instance_class', m(key_of(Old.__dict__, '__module__')), m(key_of(Old.__dict__, '__doc__'))))

RESULT = R
