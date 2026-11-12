K = lambda value: value
def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

big = 2**70
RESULT = (
    K('%o') % 8, K('%o') % -8, K('%x') % 255, K('%X') % 255, K('%x') % -255, K('%u') % 5, K('%u') % -5, K('%#x') % 0, K('%#X') % 0, K('%#o') % 0,
    K('%o') % big, K('%#o') % big, K('%x') % big, K('%#X') % big, K('%d') % -big, K('%.30d') % big, K('%#.5o') % 8, K('%#.5x') % 31, K('%.0d') % 0,
    K('%d') % 2**62, K('%x') % 2**63, K('%X') % -2**63, K('%#o') % 2**64, K('%.3o') % 8L, K('%#.3o') % 8L,
    K('%d') % 1.0e15, K('%x') % 255.9, K('%o') % -8.5, K('%c') % 65, K('%c') % 'z', K('%5c|') % 'q', K('%-3c|') % 66,
    err(lambda: K('%c') % 'ab'), err(lambda: K('%c') % 256), err(lambda: K('%c') % -1), err(lambda: K('%c') % 1.5), err(lambda: K('%c') % []),
    len(K('%.116d') % 1), err(lambda: K('%.117d') % 1), len(K('%.200d') % 1L),
)
