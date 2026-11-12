def K(x):
    return x

def attempt(function, *args, **keywords):
    try:
        return ('ok', function(*args, **keywords))
    except BaseException as e:
        return (type(e).__name__, e.args)

def accepted(function, *args):
    try:
        function(*args)
        return 'accepted'
    except BaseException as e:
        return (type(e).__name__, e.args)

def windows():
    import _winreg as w
    T = w.HKEYType
    H = w.HKEY_CURRENT_USER

    # Every PyHKEY instance comes from the host registry, so only the type
    # and its unbound methods are exact.
    unbound = [
        attempt(T), attempt(T.Close, K(5)), attempt(T.Detach, K(5)), attempt(T.__enter__, K(5)),
        attempt(T.__exit__, K(5)), attempt(T.__int__, K(5)), attempt(T.__nonzero__, K(5)),
        attempt(T.__add__, K(5), K(5)), attempt(T.__str__, K(5)), attempt(T.Close),
        attempt(T.handle.__get__, K(5), int), attempt(type, 'Sub', (T,), {}),
    ]

    names = sorted(name for name in dir(w) if not name.startswith('__'))
    constants = [(name, getattr(w, name)) for name in names if name.isupper()]
    arguments = [
        attempt(w.CloseKey), attempt(w.CloseKey, K(5)), attempt(w.CloseKey, None), attempt(w.CloseKey, K(1), K(2)),
        attempt(w.ConnectRegistry, K(5), H), attempt(w.ConnectRegistry, None, None), attempt(w.ConnectRegistry, None, K('x')),
        attempt(w.ConnectRegistry, None, K(2 ** 64)), attempt(w.ConnectRegistry, None, K(1.5)),
        attempt(w.CreateKey, H), attempt(w.CreateKey, None, K('a')), attempt(w.CreateKey, H, K(5)),
        attempt(w.CreateKey, K('x'), K('a')), attempt(w.CreateKey, H, K('a\0')),
        attempt(w.CreateKeyEx, H, K('a'), K('x')), attempt(w.CreateKeyEx, H, K('a'), K(0), K('x')),
        attempt(w.CreateKeyEx, H, K('a'), K(0), K(1), K(2)),
        attempt(w.DeleteKey, H, None), attempt(w.DeleteKey, H, K(5)), attempt(w.DeleteKeyEx, H, None),
        attempt(w.DeleteKeyEx, H, K('a'), K('x')), attempt(w.DeleteValue, H, K(5)),
        attempt(w.EnumKey, H, K('x')), attempt(w.EnumKey, H, K(2 ** 64)), attempt(w.EnumValue, H),
        attempt(w.EnumValue, None, K(0)),
        attempt(w.ExpandEnvironmentStrings, K('abc')), attempt(w.ExpandEnvironmentStrings, K(5)),
        attempt(w.FlushKey, K('x')), attempt(w.LoadKey, H, K('a'), None), attempt(w.LoadKey, H, None, K('a')),
        attempt(w.OpenKey, H), attempt(w.OpenKey, H, K('a'), K('x')), attempt(w.OpenKeyEx, H, K(5)),
        attempt(w.OpenKey, H, None, K(0), K(2 ** 64)), attempt(w.OpenKey, a=K(1)), attempt(w.OpenKeyEx, a=K(1)),
        attempt(w.QueryInfoKey, K('x')), attempt(w.QueryValue, H, K(5)), attempt(w.QueryValueEx, H, K(5)),
        attempt(w.SaveKey, H, None), attempt(w.SetValue, H, None, K(2), K('x')), attempt(w.SetValue, H, None, K('a'), K('x')),
        attempt(w.SetValue, K('x'), None, K(2), K('x')), attempt(w.SetValue, H, None, K(1), K(5)),
        attempt(w.SetValue, H, K(5), K(1), K('x')),
        attempt(w.SetValueEx, H, K(5), K(0), K(1), K('x')), attempt(w.SetValueEx, H, K('v'), K(0), K('x'), K('x')),
        attempt(w.SetValueEx, K('k'), K('v'), K(0), K(1), K('x')),
        attempt(w.SetValueEx, H, K('v'), K(0), w.REG_DWORD, K('x')), attempt(w.SetValueEx, H, K('v'), K(0), w.REG_SZ, K(5)),
        attempt(w.SetValueEx, H, K('v'), K(0), w.REG_MULTI_SZ, K('x')),
        attempt(w.SetValueEx, H, K('v'), K(0), w.REG_MULTI_SZ, [K('a'), K(5)]),
        attempt(w.SetValueEx, H, K('v'), K(0), w.REG_BINARY, K(5)), attempt(w.SetValueEx, H, K('v'), K(0), K(99), [K(1)]),
        attempt(w.SetValueEx, H, K('v'), K(0), w.REG_BINARY, memoryview(K('ab'))),
        attempt(w.DisableReflectionKey, K('x')), attempt(w.EnableReflectionKey), attempt(w.QueryReflectionKey, None),
    ]
    # The interpreter stores __module__ and a refusing __new__ in the dict
    # of every native type; CPython's static PyHKEY type has neither.
    slots = sorted(name for name in T.__dict__ if name not in ('__module__', '__new__'))
    type_facts = [T.__name__, T.__module__, slots, type(T.__dict__['handle']).__name__, w.error is WindowsError]
    return [unbound, names, constants, arguments, type_facts]

RESULT = windows()
