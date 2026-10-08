import ctypes

if not ctypes.windll.user32.LockWorkStation():
    raise RuntimeError("Windows could not be locked.")