import socket
import struct
import bits
import dns

names = [ '',
          'A', 'NS', 'MD', 'MF', 'CNAME', 'SOA', 'MB', 'MG', 'MR', 'NULL', 
          'WKS', 'PTR', 'HINFO', 'MINFO', 'MX', 'TXT', 'RP', 'AFSDB', 'X25',
          'ISDN', 'RT', 'NSAP', 'NSAP-PTR', 'SIG', 'KEY', 'PX', 'GPOS', 'AAAA',
          'LOC', 'NXT', 'EID', 'NIMLOC', 'SRV', 'ATMA', 'NAPTR', 'KX', 'CERT',
          'A6', 'DNAME', 'SINK', 'OPT', 'APL', 'DS', 'SSHFP', 'IPSECKEY',
          'RRSIG', 'NSEC', 'DNSKEY', 'DHCID', 'NSEC3', 'NSEC3PARAM', 'TLSA',
          '', '', 'HIP', 'NINFO', 'RKEY', 'TALINK', 'CDS'
        ]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#s.bind(('', 15353))
s.bind(('', 53))

while True:
  message, source = s.recvfrom(4096)
  print message
  print source

  ID, fields, QDCount, ANCount, NSCount, ARCount                                 \
                  = struct.unpack_from('!H H H H H H', message)

  message = message[12:]

  QR, opcode, AA, TC, RD, RA, Zero, RCode                                        \
                  = bits.extractBits('1 4 1 1 1 1 3 4', fields)

  urlParts, message = dns.decodeDnsUrl(message)

  QType, QClass = struct.unpack_from('!H H', message)

  print "ID:",ID
  print "QR:",QR
  print "opcode:",opcode
  print "AA:",AA
  print "TC:",TC
  print "RD:",RD
  print "RA:",RA
  print "Zero:",Zero
  print "RCode:",RCode
  print "QDCount:",QDCount
  print "ANCount:",ANCount
  print "NSCount:",NSCount
  print "ARCount:",ARCount
  print "URL:",urlParts
  print "QType:",names[QType]
  print "QClass:",QClass
