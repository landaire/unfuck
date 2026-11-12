# -*- coding: utf-8 -*-
class Namespace(object):
    def __init__(self):
        self.data = {}

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value

    def __delitem__(self, key):
        del self.data[key]


into = {}
exec 'a = 1\nb = a + 1\ndef f(x):\n    return x * b\n' in into
in_dict = (into['a'], into['b'], into['f'](3), sorted(into.keys()), into['f'].__module__)

pair_globals = {'base': 10}
pair_locals = {}
exec 'global g\ng = base\nl = base + 1' in pair_globals, pair_locals
exec ('t = 1', pair_globals)
exec ('t = 2', pair_globals, pair_locals)
exec_pair = (pair_globals['g'], pair_globals['t'], sorted(pair_locals.items()))

mapping = Namespace()
exec 'x = 1\ny = x + 1\ndel x' in {}, mapping
mapping_locals = sorted(mapping.data.items())

unicode_source = {}
exec u'text = "\xe9"\nchars = u"\xe9"' in unicode_source
unicode_result = (unicode_source['text'], unicode_source['chars'])

future_source = {}
exec 'quotient = 1 / 2' in future_source


def bare_exec(argument):
    local = 1
    exec 'local = local + argument\nnew_name = local * 2'
    return local, new_name


def nested_exec():
    namespace = {}
    exec 'def outer():\n    v = 1\n    def inner():\n        return v + 1\n    return inner()\nresult = outer()' in namespace
    return namespace['result']


def exec_code_object():
    code = compile('created = 5', '<compiled>', 'exec')
    namespace = {}
    exec code in namespace
    return namespace['created']


RESULT = (in_dict, exec_pair, mapping_locals, unicode_result, future_source['quotient'], bare_exec(2), nested_exec(), exec_code_object())
