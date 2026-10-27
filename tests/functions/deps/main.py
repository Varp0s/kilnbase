import six


def handler(request):
    return {"six": six.__version__, "path": six.__file__}
