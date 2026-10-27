import os


def handler(request):
    keys = ("API_TOKEN", "SHARED", "ONLY_WHOAMI", "PATH")
    return {k: os.environ.get(k) for k in keys} | {"files": os.listdir("/functions")}
