import sys

print
print 1
print 1, 2
print 1,
print >> sys.stderr
print >> sys.stderr, 'error'
print >> sys.stderr, 'error', 'more',
print (1, 2)

def in_function(stream, value):
    print >>stream, value
    print value,
