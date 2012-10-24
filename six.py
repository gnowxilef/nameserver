import sys

PY3 = sys.version_info[0] == 3

def b(s):
  if PY3:
    if type(s) == bytes:
      return s
    else:
      return s.encode('latin-1')
  else:
    return s

def s(b):
  if PY3:
    if type(b) == str:
      return b
    else:
      return str(b, 'latin-1')
  else:
    return b
