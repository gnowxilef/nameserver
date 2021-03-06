import struct
import socket
import struct
import bits
import sys
from six import b,s

dns_records = ['',
               'A', 'NS', 'MD', 'MF', 'CNAME', 'SOA', 'MB', 'MG', 'MR', 'NULL', 
               'WKS', 'PTR', 'HINFO', 'MINFO', 'MX', 'TXT', 'RP', 'AFSDB', 
               'X25', 'ISDN', 'RT', 'NSAP', 'NSAP-PTR', 'SIG', 'KEY', 'PX', 
               'GPOS', 'AAAA', 'LOC', 'NXT', 'EID', 'NIMLOC', 'SRV', 'ATMA', 
               'NAPTR', 'KX', 'CERT', 'A6', 'DNAME', 'SINK', 'OPT', 'APL', 
               'DS', 'SSHFP', 'IPSECKEY', 'RRSIG', 'NSEC', 'DNSKEY', 'DHCID', 
               'NSEC3', 'NSEC3PARAM', 'TLSA', '', '', 'HIP', 'NINFO', 'RKEY', 
               'TALINK', 'CDS']

extra_dns_records = { 255: '*' }


def cleanNSLine(line):
  line = line.strip()
  if line.startswith(';'):
    return ''
  else:
    return line.split(';')[0]


def readEffectiveNSLine(f):
  while True:
    l = f.readline()
    if l == '':
      return None

    l = cleanNSLine(l)
    
    if l != '':
      return l


def readNSEntry(f):
  line = readEffectiveNSLine(f)

  if line == None:
    return None

  parens = 0

  while line.count('(') != line.count(')'):
    n = readEffectiveNSLine(f)
    if n == None:
      raise Exception("Mismatched Parentheses: " + line)

    line += " " + n

  while line.count('(') > 0 and line.index('(') < line.index(')'):
    line = line.replace('(', '', 1)
    line = line[::-1].replace(')', '', 1)[::-1]

  if '(' in line or ')' in line:
    raise Exception("Mismatched Parentheses: " + line)

  return line


def loadNSFile(fname):
  entries = {}

  f = open(fname)

  while True:
    entry = readNSEntry(f)
    if entry == None:
      break

    parts = entry.split()
    if len(parts) > 2:
      if parts[2] == 'SOA':
        name, Class, Type, Start, Manager, serial, refresh, retry, expire,     \
        minimum = parts
        if name not in entries:
          entries[name] = {}
        if Type not in entries[name]:
          entries[name][Type] = []
        entries[name][Type].append([Start, Manager, int(serial), int(refresh), 
                                    int(retry), int(expire), int(minimum)])
      elif len(parts) == 4:
        name, TTL, Type, Data = parts
        if name not in entries:
          entries[name] = {}
        if Type not in entries[name]:
          entries[name][Type] = []
        entries[name][Type].append([int(TTL), Data])
    # line = f.readline()
  return entries


def readDNSName(string):
  """
  Reads a name entry in DNS format
  """
  chars = struct.unpack_from('!B', b(string))[0]
  string = string[1:]
  name_parts = []
  while chars > 0:
    name_parts.append(s(string[:chars]))
    string = string[chars:]
    chars = struct.unpack_from('!B',b(string))[0]
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
  retval = b('')
  for part in parts:
    if len(part) > 0:
      retval += struct.pack('!B', len(part))
      retval += b(part)
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

    self.QType, self.QClass = struct.unpack_from('!H H', b(m))

    return m[4:]

  def createAnswers(self, data):
    """
    Create an Answer from the Question
    """
    
    answers = []
    nameStr = '.'.join(self.name) + '.'
    if nameStr in data:
      records = data[nameStr]
      if self.QType == 255:
        for typeStr in records:
          record = records[typeStr]
          for entry in record:
            answers.append(Resource(self.name, typeStr, entry))
      else:
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
          r = Resource(self.name, t, row)
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
    if self.QType in range(len(dns_records)):
      retval += '\t' + dns_records[self.QType]
    elif self.QType in extra_dns_records:
      retval += '\t' + extra_dns_records[self.QType]
    else:
      retval += "\t???"
    return retval
  

class Resource:
  def __init__(self, entryName = None, entryType = None, entry = None):
    if entryName != None and entryType != None and entry != None:
      self.name = entryName
      self.RType = dns_records.index(entryType)
      self.RClass = 1 # Internet
      self.TTL = entry[0]
      if entryType == 'SOA':
        self.TTL = 0
        self.RData  = writeDNSName(entry[0])
        self.RData += writeDNSName(entry[1])
        self.RData += struct.pack('!I', entry[2])
        self.RData += struct.pack('!I', entry[3])
        self.RData += struct.pack('!I', entry[4])
        self.RData += struct.pack('!I', entry[5])
        self.RData += struct.pack('!I', entry[6])
        self.RDLength = len(self.RData)
      elif entryType == 'A':
        octets = [int(n) for n in entry[1].split('.')]
        self.RDLength = len(octets)
        self.RData = b('')
        for octet in octets:
          self.RData += struct.pack('!B', octet)
      elif entryType in ['NS', 'CNAME']:
        self.RData = writeDNSName(entry[1])
        self.RDLength = len(self.RData)
    else:
      self.name = 0
      self.RType = 0
      self.RClass = 1
      self.TTL = 0
      self.RDLength = 0
      self.RData = ""

  def readFrom(self, m):
    """
    Reads the data for the Resource from a string
    """
    self.name, m = readDNSName(m)

    self.RType, self.RClass, self.TTL, self.RDLength                           \
                = struct.unpack_from('!H H I H', b(m))

    m = m[10:]

    self.RData = m[:self.RDLength]

    return m[self.RDLength:]

  def pack(self):
    """
    Packs the data for the Resource into the response
    """
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
  def __init__(self, message=None, source=None, ID=None):
    if message != None and source != None:
      self.message = message
      self.source = source
      self.parseMessage()
    elif ID != None:
      self.ID = ID
      self.QR = 0
      self.opcode = 0
      self.AA = 0
      self.TC = 0
      self.RD = 0
      self.RA = 0
      self.zero = 0
      self.RCode = 0
      self.QDCount = 0
      self.ANCount = 0
      self.NSCount = 0
      self.ARCount = 0
      self.questions = []
      self.answers = []
      self.authority = []
      self.additional = []

  def setMessage(self, m):
    self.message = m

  def setSource(self, s):
    self.source = s

  def parseMessage(self):
    m = self.message
    self.ID, fields, self.QDCount, self.ANCount, self.NSCount, self.ARCount   \
      = struct.unpack_from('!H H H H H H', m)

    m = m[12:]

    self.QR, self.opcode, self.AA, self.TC, self.RD, self.RA, self.zero,      \
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
    retval = b("")

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

  def addQuestion(self, q):
    self.QDCount += 1
    self.questions.append(q)

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
    retval.RCode = self.RCode
    retval.QDCount = self.QDCount
    retval.ANCount = self.ANCount
    retval.NSCount = self.NSCount
    retval.ARCount = self.ARCount
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
    self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.s.bind(('', port))
    self.addr, self.port = self.s.getsockname()

  def getRequest(self):
    message, source = self.s.recvfrom(4096)
    return Packet(message, source)

  def sendResponse(self, response):
    self.s.sendto(response.pack(), response.source)
