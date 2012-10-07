import socket
import struct

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('', 15353))

message, source = s.recvfrom(4096)

ID, first, second, QDCount, ANCount, NSCount, ARCount                          \
                = struct.unpack_from('!H B B H H H H', message)

message = message[10:]

QR =      (first  & 0b10000000) >> 7
opcode =  (first  & 0b01111000) >> 3
AA =      (first  & 0b00000100) >> 2
TC =      (first  & 0b00000010) >> 1
RD =      (first  & 0b00000001)
RA =      (second & 0b10000000) >> 7
Zero =    (second & 0b01110000) >> 4
RCode =   (second & 0b00001111)

print "ID:",ID
print "First Bits:",first
print "Second Bits:",second
print "QDCount:",QDCount
print "ANCount:",ANCount
print "NSCount:",NSCount
print "ARCount:",ARCount
print "message:",message
