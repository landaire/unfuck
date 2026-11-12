import pkgutil
import zipimport


def failure(function, *args, **keywords):
    try:
        function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, str(e))
    return 'no error'


RESULT = (
    failure(zipimport.zipimporter, 1),
    failure(zipimport.zipimporter, ''),
    failure(zipimport.zipimporter, u''),
    failure(zipimport.zipimporter, 'a\x00b'),
    failure(zipimport.zipimporter, path='x'),
    failure(zipimport.zipimporter),
    failure(zipimport.zipimporter, 'a', 'b'),
    failure(zipimport.zipimporter.get_code, 1, 'x'),
    failure(zipimport.zipimporter.find_module),
    failure(zipimport.zipimporter.__new__, 1),
    failure(zipimport.zipimporter.__new__, int),
    failure(zipimport.zipimporter.archive.__get__, 1),
    issubclass(zipimport.ZipImportError, ImportError),
    zipimport.ZipImportError.__module__,
    zipimport.zipimporter.__module__,
    zipimport.zipimporter.__name__,
    zipimport._zip_directory_cache,
    {zipimport.zipimporter: 1}[zipimport.zipimporter],
    pkgutil.iter_importer_modules.__name__,
    sorted(name for name in dir(zipimport) if not name.startswith('__')),
)
