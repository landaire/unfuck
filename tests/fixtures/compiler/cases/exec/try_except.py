try:
    import missing
except ImportError:
    missing = None

try:
    x = 1
except (TypeError, ValueError), error:
    x = error
except KeyError as error:
    x = error
except:
    raise
else:
    x = 2
finally:
    x = 3

def finally_return():
    try:
        return 1
    finally:
        pass

def raise_forms(kind):
    if kind == 0:
        raise
    if kind == 1:
        raise ValueError
    if kind == 2:
        raise ValueError, 'message'
    raise ValueError, 'message', None

def nested(a):
    try:
        try:
            a()
        except Exception, (first, second):
            return first
    finally:
        a = None

def handler_to_attribute(obj):
    try:
        obj()
    except Exception, obj.error:
        pass
    except Exception, obj[0]:
        pass
