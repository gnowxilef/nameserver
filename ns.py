import socket
import struct
import bits

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('', 15353))

message, source = s.recvfrom(4096)

ID, fields, QDCount, ANCount, NSCount, ARCount                          \
                = struct.unpack_from('!H H H H H H', message)

message = message[10:]

QR, opcode, AA, TC, RD, RA, Zero, RCode = bits.extractBits('1 4 1 1 1 1 3 4', fields)

print "ID:",ID
print "First Bits:",first
print "Second Bits:",second
print "QDCount:",QDCount
print "ANCount:",ANCount
print "NSCount:",NSCount
print "ARCount:",ARCount
print "message:",message
