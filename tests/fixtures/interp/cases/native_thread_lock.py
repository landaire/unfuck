import thread


def error(action):
    try:
        action()
    except Exception as e:
        return repr(e)


lock = thread.allocate_lock()
first = lock.acquire()
second = lock.acquire(0)
held = lock.locked()
lock.release()
released = lock.locked()
with lock:
    inside = lock.locked()
after = lock.locked()


class Local(thread._local):
    def __init__(self, value):
        self.value = value


local = thread._local()
local.x = 1
custom = Local(3)

errors = [error(action) for action in (
    lambda: lock.release(),
    lambda: thread._local(1),
    lambda: thread.stack_size(100),
)]

caught = None
try:
    lock.release()
except thread.error as e:
    caught = e.args

RESULT = (first, second, held, released, inside, after, lock.acquire_lock(0), lock.locked_lock(), lock.release_lock(),
          local.x, local.__dict__, custom.value, errors, caught, thread.get_ident() == thread.get_ident(),
          thread.stack_size(), thread._count(), type(lock) is thread.LockType, thread.LockType.__module__,
          thread.error.__module__, issubclass(thread.error, Exception), thread.allocate is not None,
          lock.__enter__(), lock.__exit__(None, None, None))
