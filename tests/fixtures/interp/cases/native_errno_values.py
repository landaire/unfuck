import errno

common = ['EPERM', 'ENOENT', 'ESRCH', 'EINTR', 'EIO', 'ENXIO', 'E2BIG', 'ENOEXEC', 'EBADF', 'ECHILD',
          'ENOMEM', 'EACCES', 'EFAULT', 'EBUSY', 'EEXIST', 'EXDEV', 'ENODEV', 'ENOTDIR', 'EISDIR',
          'EINVAL', 'ENFILE', 'EMFILE', 'ENOTTY', 'EFBIG', 'ENOSPC', 'ESPIPE', 'EROFS', 'EMLINK', 'EPIPE',
          'EDOM', 'ERANGE']
values = [getattr(errno, name) for name in common]
names = [errno.errorcode[value] for value in values]
consistent = all(getattr(errno, errno.errorcode[code]) == code for code in errno.errorcode)
covered = all(errno.errorcode[getattr(errno, name)] in dir(errno) for name in dir(errno) if name[:1] == 'E' and name != 'errorcode')
RESULT = (values, names, consistent, covered, isinstance(errno.errorcode, dict), errno.EDEADLK == errno.EDEADLOCK,
          errno.EWOULDBLOCK in errno.errorcode, errno.ETIMEDOUT > 0, sorted(errno.errorcode)[:5])
