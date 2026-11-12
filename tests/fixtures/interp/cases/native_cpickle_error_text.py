# str() of the cPickle exception classes.
import cPickle

out = [hasattr(cPickle, "__builtins__")]
for error_class in (cPickle.PickleError, cPickle.PicklingError, cPickle.UnpicklingError, cPickle.UnpickleableError, cPickle.BadPickleGet):
    texts = []
    for args in [(), ("x",), ("",), (0,), (5, 6), ((1, 2),), (u"\xe9",), (u"u",), (None,)]:
        try:
            texts.append(str(error_class(*args)))
        except Exception as error:
            texts.append("%s: %s" % (type(error).__name__, error))
    out.append((error_class.__name__, error_class.__module__, texts, "__str__" in vars(error_class)))

out.append(unicode(cPickle.UnpickleableError(1)))

RESULT = out
