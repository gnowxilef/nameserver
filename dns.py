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

def loadNSFile(fname):
  entries = {}

  f = file(fname)
  line = f.readline()
  while line != '':
    if line.startswith(';'): 
      line = f.readline()
      continue
    parts = line.split()
    if len(parts) > 2:
      if parts[2] == 'SOA':
        name, Class, Type, Start, Manager, Paren = parts
        serial = int(f.readline())
        refresh = int(f.readline())
        retry = int(f.readline())
        expire = int(f.readline())
        minimum = int(f.readline().split()[0])
        if name not in entries:
          entries[name] = {}
        if Type not in entries[name]:
          entries[name][Type] = []
        entries[name][Type].append([Start, Manager, serial, refresh, retry,
                                    expire, minimum])
      elif len(parts) == 4:
        name, TTL, Type, Data = parts
        if name not in entries:
          entries[name] = {}
        if Type not in entries[name]:
          entries[name][Type] = []
        entries[name][Type].append([TTL, Data])
    line = f.readline()
  return entries

def readDNSName(string):
  """
  Reads a name entry in DNS format
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

def writeDNSName(domain):
  """
  Take a list of parts and make a DNS name out of them.
  """
  if type(domain) == str:
    parts = domain.split('.')
  else:
    parts = domain
  retval = ""
  for part in parts:
    if len(part) > 0:
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
    """
    Reads data in from a file
    """
    self.name, m = readDNSName(m)

    self.QType, self.QClass = struct.unpack_from('!H H', m)

    return m[4:]

  def createAnswers(self, data):
    """
    Create an Answer from the Question
    """
    
    answers = []
    nameStr = '.'.join(self.name) + '.'
    if nameStr in data:
      records = data[nameStr]
      if dns_records[self.QType] in records:
        t = dns_records[self.QType]
        record = records[dns_records[self.QType]]
      elif dns_records[self.QType] == 'A' and 'CNAME' in records:
        t = 'CNAME'
        record = records['CNAME']
      else:
        return answers
      if type(record) == str:
        record = [record]
      for row in record:
        r = Resource()
        r.name = self.name
        r.RType = dns_records.index(t)
        if t == 'SOA':
          r.RData  = writeDNSName(row[0])
          r.RData += writeDNSName(row[1])
          r.RData += struct.pack('!I', row[2])
          r.RData += struct.pack('!I', row[3])
          r.RData += struct.pack('!I', row[4])
          r.RData += struct.pack('!I', row[5])
          r.RData += struct.pack('!I', row[6])
          r.RDLength = len(r.RData)
        else:
          data = row[1]
          r.DisplayData = data
          if t == 'A':
            octets = [int(n) for n in data.split('.')]
            r.RDLength = len(octets)
            r.RData = ''
            for octet in octets:
              r.RData += struct.pack('!B', octet)
          elif t == 'NS' or t == 'CNAME':
            r.RData = writeDNSName(data)
            r.RDLength = len(r.RData)
          r.TTL = int(row[0])
        answers.append(r)
    return answers
 
  def pack(self):
    """
    Packs the data from the Question into the response
    """
    retval = writeDNSName(self.name)
    retval += struct.pack('!H H', self.QType, self.QClass)
    return retval

  def __str__(self):
    retval = ""
    retval += '.'.join(self.name)
    retval += '\t' + dns_records[self.QType]
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
    retval += '.'.join(self.name) + '.'
    retval += '\t' + str(self.TTL) + "\tIN"
    retval += '\t' + dns_records[self.RType]
    t = dns_records[self.RType]
    if t == 'A':
      a,b,c,d = struct.unpack_from('!B B B B', self.RData)
      retval += '\t%d.%d.%d.%d' % (a,b,c,d)
    elif t == 'NS' or t == 'CNAME':
      parts = readDNSName(self.RData)[0]
      retval += '\t' + '.'.join(parts) + '.'
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
    retval.AA = 1
    retval.RA = 0
    retval.RCode = 0

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
    self.s.sendto(response.pack(), response.source)

if __name__ == "__main__":
  import doctest
  import sys
  sys.exit(doctest.testmod()[0])
