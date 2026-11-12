import gc

def attempt(function, *args, **keywords):
    try:
        return function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, e.args)

initially = gc.isenabled()
gc.disable()
disabled = gc.isenabled()
gc.disable()
still_disabled = gc.isenabled()
gc.enable()
enabled = gc.isenabled()

thresholds = gc.get_threshold()
gc.set_threshold(100)
partial = gc.get_threshold()
gc.set_threshold(5, 6, 7)
full = gc.get_threshold()
gc.set_threshold(*thresholds)

debug = gc.get_debug()
gc.set_debug(gc.DEBUG_STATS | gc.DEBUG_SAVEALL)
changed = gc.get_debug()
gc.set_debug(debug)

errors = [
    attempt(gc.collect, 3),
    attempt(gc.collect, -1),
    attempt(gc.collect, generation=7),
    attempt(gc.collect, 'x'),
    attempt(gc.set_debug, 'x'),
    attempt(gc.set_debug, 1.5),
    attempt(gc.set_debug),
    attempt(gc.enable, 1),
    attempt(gc.set_threshold),
    attempt(gc.set_threshold, 1, 2, 3, 4),
    attempt(gc.is_tracked),
]
tracked = [gc.is_tracked(value) for value in (1, 2 ** 80, 1.5, 'text', u'text', None, True)]
constants = (gc.DEBUG_STATS, gc.DEBUG_COLLECTABLE, gc.DEBUG_UNCOLLECTABLE, gc.DEBUG_INSTANCES,
             gc.DEBUG_OBJECTS, gc.DEBUG_SAVEALL, gc.DEBUG_LEAK)
RESULT = (initially, disabled, still_disabled, enabled, thresholds, partial, full, gc.get_threshold(),
          debug, changed, gc.get_debug(), errors, tracked, constants, gc.garbage)
