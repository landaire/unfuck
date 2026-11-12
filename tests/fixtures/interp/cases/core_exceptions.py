log = []


def returns_in_finally():
    try:
        return 'try'
    finally:
        log.append('finally')


def break_in_finally():
    for item in (1, 2, 3):
        try:
            if item == 2:
                break
        finally:
            log.append(item)
    return item


def nested():
    try:
        try:
            raise ValueError('inner')
        except KeyError:
            log.append('wrong')
        finally:
            log.append('inner finally')
    except ValueError as error:
        return error.args


def reraise():
    try:
        try:
            raise TypeError('first')
        except TypeError:
            raise
    except TypeError as error:
        return str(error)


class Suppress(object):
    def __enter__(self):
        log.append('enter')
        return self

    def __exit__(self, kind, value, traceback):
        log.append(kind.__name__ if kind else None)
        return True


def suppressed():
    with Suppress() as manager:
        raise IndexError('hidden')
    return manager.__class__.__name__


class Custom(Exception):
    def __init__(self, code):
        Exception.__init__(self, 'code %d' % code)
        self.code = code


def custom():
    try:
        raise Custom(7)
    except Exception as error:
        return (error.code, error.args, repr(error))


def continue_in_try():
    total = 0
    for item in (1, 2, 3, 4):
        try:
            if item % 2:
                continue
            total += item
        finally:
            total += 100
    return total


RESULT = (returns_in_finally(), break_in_finally(), nested(), reraise(), suppressed(), custom(), continue_in_try(), log)
