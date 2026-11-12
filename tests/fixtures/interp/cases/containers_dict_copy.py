class Sub(dict):
    pass

d = {}
for k in range(0, 96, 8):
    d[k] = k
for k in range(0, 96, 16):
    del d[k]
copied = d.copy()
constructed = dict(d)
sub = Sub(d)
sub_copy = sub.copy()
d[200] = 'only original'
shallow = {'list': [1]}
shallow_copy = shallow.copy()
shallow_copy['list'].append(2)

RESULT = (d.keys(), copied.keys(), constructed.keys(), type(sub_copy).__name__, sub_copy == sub, 200 in copied, shallow, len(copied))
