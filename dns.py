import struct
import socket
import struct
import bits

dns_records = [ '',
                'A', 'NS', 'MD', 'MF', 'CNAME', 'SOA', 'MB', 'MG', 'MR', 'NULL', 
                'WKS', 'PTR', 'HINFO', 'MINFO', 'MX', 'TXT', 'RP', 'AFSDB', 
                'X25', 'ISDN', 'RT', 'NSAP', 'NSAP-PTR', 'SIG', 'KEY', 'PX', 
                'GPOS', 'AAAA', 'LOC', 'NXT', 'EID', 'NIMLOC', 'SRV', 'ATMA', 
                'NAPTR', 'KX', 'CERT', 'A6', 'DNAME', 'SINK', 'OPT', 'APL', 
                'DS', 'SSHFP', 'IPSECKEY', 'RRSIG', 'NSEC', 'DNSKEY', 'DHCID', 
                'NSEC3', 'NSEC3PARAM', 'TLSA', '', '', 'HIP', 'NINFO', 'RKEY', 
                'TALINK', 'CDS'
              ]

def readDNSName(string):
  r"""
  Reads a name entry in DNS format
  >>> readDNSName('\x03www\x06zmbush\x03com\x00')
  (['www', 'zmbush', 'com'], '')
  
  >>> readDNSName('\x06static\x06zmbush\x03com\x00remain')
  (['static', 'zmbush', 'com'], 'remain')
  """
  chars = struct.unpack_from('!B', string)[0]
  string = string[1:]
  name_parts = []
  while chars > 0:
    name_parts.append(string[:chars])
    string = string[chars:]
    chars = struct.unpack_from('!B',string)[0]
    string = string[1:]
  return (name_parts, string)

def writeDNSName(parts):
  r"""
  Take a list of parts and make a DNS name out of them.
  >>> writeDNSName(['static', 'zmbush', 'com'])
  '\x06static\x06zmbush\x03com\x00'
  """
  retval = ""
  for part in parts:
    retval += struct.pack('!B', len(part))
    retval += part
  retval += struct.pack('!B', 0)
  return retval

class Question:
  def __init__(self):
    self.name = ""
    self.QType = 0
    self.QClass = 1

  def readFrom(self, m):
    r"""
    Reads data in from a file
    >>> q = Question()
    >>> q.readFrom('\x03www\x06zmbush\x03com\x00\x00\x01\x00\x01extra')
    'extra'
    >>> q.name
    ['www', 'zmbush', 'com']
    >>> q.QType
    1
    >>> q.QClass
    1
    """
    self.name, m = readDNSName(m)

    self.QType, self.QClass = struct.unpack_from('!H H', m)

    return m[4:]

  def createAnswer(self, data):
    r"""
    Create an Answer from the Question
    
    >>> q = Question()
    >>> q.readFrom('\x03www\x00\x00\x01\x00\x01')
    ''
    >>> r = q.createAnswer({'www':{'A':'255.0.0.1'}})
    >>> r.RType
    1
    >>> r.RData
    '\xff\x00\x00\x01'
    >>> r.RDLength
    4
    >>> r.name
    ['www']
    >>> r.TTL
    180
    """
    r = Resource()
    if '.'.join(self.name) in data:
      records = data['.'.join(self.name)]
      if dns_records[self.QType] in records:
        data = records[dns_records[self.QType]]
        r.name = self.name
        r.RType = self.QType
        t = dns_records[self.QType]
        if t == 'A':
          octets = [int(n) for n in data.split('.')]
          r.RDLength = len(octets)
          r.RData = ''
          for octet in octets:
            r.RData += struct.pack('!B', octet)
        elif t == 'NS':
          r.RDLength = len(data)
          r.RData = data
        r.TTL = 180
        return r
    return
 
  def pack(self):
    r"""
    Packs the data from the Question into the response

    >>> q = Question()
    >>> rawq = '\x03www\x00\x00\x01\x00\x01'
    >>> q.readFrom(rawq + 'extra')
    'extra'
    >>> q.pack() == rawq
    True
    """
    retval = writeDNSName(self.name)
    retval += struct.pack('!H H', self.QType, self.QClass)
    return retval

  def __str__(self):
    retval = ""
    retval += '.'.join(self.name)
    retval += '\t' + dns_records[self.QType]
    retval += '\n' + repr(self.pack())
    return retval
  

class Resource:
  def __init__(self):
    self.name = 0
    self.RType = 0
    self.RClass = 1
    self.TTL = 0
    self.RDLength = 0
    self.RData = ""

  def readFrom(self, m):
    self.name, m = readDNSName(m)

    self.RType, self.RClass, self.TTL, self.RDLength                           \
                = struct.unpack_from('!H H I H', m)

    m = m[10:]

    self.RData = m[:self.RDLength]

    return m[self.RDLength:]

  def pack(self):
    retval = writeDNSName(self.name)
    retval += struct.pack('!H H I H', self.RType, self.RClass, self.TTL,
                          self.RDLength)
    retval += self.RData
    return retval

  def __str__(self):
    retval = ""
    retval += '.'.join(self.name)
    retval += '\t' + dns_records[self.RType]
    retval += '\t' + self.RData
    retval += '\n' + repr(self.pack())
    return retval

class Packet:
  def __init__(self, message=None, source=None):
    if message != None and source != None:
      self.message = message
      self.source = source
      self.parseMessage()


  def setMessage(self, m):
    self.message = m

  def setSource(self, s):
    self.source = s

  def parseMessage(self):
    m = self.message
    self.ID, fields, self.QDCount, self.ANCount, self.NSCount, self.ARCount    \
      = struct.unpack_from('!H H H H H H', m)

    m = m[12:]

    self.QR, self.opcode, self.AA, self.TC, self.RD, self.RA, self.zero,       \
      self.RCode = bits.extractBits('1 4 1 1 1 1 3 4', fields)
    
    self.questions = []
    self.answers = []
    self.authority = []
    self.additional = []

    for n in range(self.QDCount):
      q = Question()
      m = q.readFrom(m)
      self.questions.append(q)

    for n in range(self.ANCount):
      r = Resource()
      m = r.readFrom(m)
      self.answers.append(r)

    for n in range(self.NSCount):
      r = Resource()
      m = r.readFrom(m)
      self.authority.append(r)
    
    for n in range(self.ARCount):
      r = Resource()
      m = r.readFrom(m)
      self.additional.append(r)

  def pack(self):
    retval = ""

    fields = bits.packBits('1 4 1 1 1 1 3 4', self.QR, self.opcode, self.AA, 
                           self.TC, self.RD, self.RA, self.zero, self.RCode)
    
    retval += struct.pack('!H H H H H H', self.ID, fields, self.QDCount,
                          self.ANCount, self.NSCount, self.ARCount)
    
    for n in range(self.QDCount):
      retval += self.questions[n].pack()
    for n in range(self.ANCount):
      retval += self.answers[n].pack()
    for n in range(self.NSCount):
      retval += self.authority[n].pack()
    for n in range(self.ARCount):
      retval += self.additional[n].pack()
    return retval

  def addAnswer(self, a):
    self.ANCount += 1
    self.answers.append(a)

  def copy(self):
    retval = Packet()
    
    retval.message = self.message
    retval.source = self.source

    retval.ID = self.ID
    retval.QR = self.QR
    retval.opcode = self.opcode
    retval.AA = self.AA
    retval.TC = self.TC
    retval.RD = self.RD
    retval.RA = self.RA
    retval.zero = self.zero
    retval.RCode  = self.RCode
    retval.QDCount  = self.QDCount
    retval.ANCount  = self.ANCount
    retval.NSCount  = self.NSCount
    retval.ARCount  = self.ARCount
    retval.questions = list(self.questions)
    retval.answers = list(self.answers)
    retval.authority = list(self.authority)
    retval.additional = list(self.additional)

    return retval

  def makeResponse(self):
    retval = self.copy()

    retval.QR = 1
    retval.AA = 0
    retval.RA = 0
    retval.RCode = 0
    retval.questions = []
    retval.QDCount = 0

    retval.answers = []
    retval.ANCount = 0

    retval.authority = []
    retval.NSCount = 0

    retval.additional = []
    retval.ARCount = 0

    return retval

  def __str__(self):
    retval = ""
    if self.QR == 0:
      retval += "Request from: %s:%s" % self.source
    else:
      retval += "Response for: %s:%s" % self.source
    if self.QDCount > 0:
      retval += "\nQuestions:"
      for n in range(self.QDCount):
        retval += '\n\t' + str(self.questions[n])
    if self.ANCount > 0:
      retval += "\nAnswers:"
      for n in range(self.ANCount):
        retval += '\n\t' + str(self.answers[n])
    if self.NSCount > 0:
      retval += "\nAuthority:"
      for n in range(self.NSCount):
        retval += '\n\t' + str(self.authority[n])
    if self.ARCount > 0:
      retval += "\nAdditional:"
      for n in range(self.ARCount):
        retval += '\n\t' + str(self.additional[n])
    return retval

class Server:
  def __init__(self, port):
    self.port = port
    self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.s.bind(('', self.port))

  def getRequest(self):
    message, source = self.s.recvfrom(4096)
    return Packet(message, source)

  def sendResponse(self, response):
    print "Sending: " + repr(response.pack())
    self.s.sendto(response.pack(), response.source)

if __name__ == "__main__":
  import doctest
  doctest.testmod()
