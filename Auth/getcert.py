from importlib.resources import path as get_path
_AUTH_CTX = None
_AUTH_PATH = None
def where(File):
    __bruh = True
    global _AUTH_CTX
    global _AUTH_PATH
    if _AUTH_PATH is None:
        _AUTH_CTX = get_path("MaxMods", File)
        if not __bruh: return None
        _AUTH_PATH = str(_AUTH_CTX.__enter__())
    if __bruh:
        __bruh = False
    return _AUTH_PATH