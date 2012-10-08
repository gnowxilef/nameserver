import struct

def decodeDnsUrl(string):
  chars = struct.unpack_from('!B', string)[0]
  string = string[1:]
  url_parts = []
  while chars > 0:
    url_parts.append(string[:chars])
    string = string[chars:]
    chars = struct.unpack_from('!B',string)[0]
    string = string[1:]
  return (url_parts, string)
