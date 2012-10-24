from dns import *
from six import b

import pytest
import os
import threading
import socket

def test_load_ns_file():
  f = open('test.ns', 'w')
  f.write('py.zmbush.com. IN SOA ns.zmbush.com. zach.zmbush.com. (\n')
  f.write('2012101100\n')
  f.write('1800\n')
  f.write('300\n')
  f.write('604800\n')
  f.write('800 )\n')
  f.write('py.zmbush.com. 3600 A 0.0.0.0')
  f.close()

  dnsEntries = loadNSFile('test.ns')
  assert dnsEntries['py.zmbush.com.']['A'][0] == [3600, '0.0.0.0']
  assert dnsEntries['py.zmbush.com.']['SOA'][0] == ['ns.zmbush.com.',
                                                  'zach.zmbush.com.',
                                                  2012101100, 1800, 300, 
                                                  604800, 800]

  os.remove('test.ns')


class TestReadDnsName:
  def test_no_extra(self):
    url, remain = readDNSName('\x03www\x06zmbush\x03com\x00')
    assert url == ['www', 'zmbush', 'com']
    assert remain == ''

  def test_extra(self):
    url, remain = readDNSName('\x03www\x06zmbush\x03com\x00remain')
    assert url == ['www', 'zmbush', 'com']
    assert remain == 'remain'

class TestWriteDnsName:
  def test_list(self):
    name = writeDNSName(['static', 'zmbush', 'com'])
    assert name == b('\x06static\x06zmbush\x03com\x00')

  def test_string(self):
    name = writeDNSName('static.zmbush.com')
    assert name == b('\x06static\x06zmbush\x03com\x00')

  def test_string_with_dot(self):
    name = writeDNSName('static.zmbush.com.')
    assert name == b('\x06static\x06zmbush\x03com\x00')

class TestQuestion:
  def test_read_from(self):
    q = Question()
    r = q.readFrom('\x03www\x06zmbush\x03com\x00\x00\x01\x00\x01extra')
    assert r == 'extra'
    assert q.name == ['www', 'zmbush', 'com']
    assert q.QType == 1
    assert q.QClass == 1

  def test_create_answer(self): 
    q = Question()
    r = q.readFrom('\x03www\x00\x00\x01\x00\x01')
    assert r == ''
    answers = q.createAnswers({'www.':{'A':[[180,'255.0.0.1']]}})
    assert len(answers) == 1
    answer = answers[0]
    assert answer.RType == 1
    assert answer.RData == b('\xff\x00\x00\x01')
    assert answer.RDLength == 4
    assert answer.name == ['www']
    assert answer.TTL == 180

  def test_pack(self):
    q = Question()
    rawq = b('\x03www\x00\x00\x01\x00\x01')
    assert q.readFrom(rawq + b('extra')) == b('extra')
    assert q.pack() == rawq

class TestResource:
  @pytest.fixture
  def data(self):
    data = writeDNSName(['www'])
    data += b('\x00\x01') # RType
    data += b('\x00\x01') # RClass
    data += b('\x00\x00\x00\x10') # TTL
    data += b('\x00\x04') # RDLength
    data += b('\xff\x00\x00\x01') # RData
    return data

  def test_read_from(self, data):
    r = Resource()
    extra = r.readFrom(data + b('extra'))
    assert extra == b('extra')
    assert r.name == [b('www')]
    assert r.RType == 1
    assert r.RClass == 1
    assert r.TTL == 16
    assert r.RDLength == 4
    assert r.RData == b('\xff\x00\x00\x01')

  def test_pack(self, data):
    r = Resource()
    r.readFrom(data)
    assert r.pack() == data

class TestPacket:
  @pytest.fixture
  def data(self):
    data = b('\x00\x01') # ID
    data += b('\x00\x00') # flags
    data += b('\x00\x01') # QDCount
    data += b('\x00\x00') # ANCount
    data += b('\x00\x00') # NSCount
    data += b('\x00\x00') # ARCount
    data += writeDNSName('www.zmbush.com.')
    data += b('\x00\x01') # RType
    data += b('\x00\x01') # RClass
    return data

  def test_parse_message(self, data):
    p = Packet()
    p.setMessage(data)
    p.setSource((0, 0))
    p.parseMessage()
    assert p.ID == 1
    assert p.QDCount == 1
    assert len(p.questions) == 1

  def test_pack(self, data):
    p = Packet(data, (0, 0))
    assert p.pack() == data
 
class TestEverything:
  def test_send_receive(self):
    def server(s):
      req = s.getRequest()
      resp = req.makeResponse()

      for question in req.questions:
        answers = question.createAnswers({'www.zmbush.com.':{'A':[[180,'127.0.0.1']]}})
        for a in answers:
          resp.addAnswer(a)

      s.sendResponse(resp)

    def client(response, port):
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      sock.bind(('', 0))
      q = Question()
      q.name = ['www', 'zmbush', 'com']
      q.QType = dns_records.index('A') 

      p = Packet(ID=1000)
      p.addQuestion(q)

      sock.sendto(p.pack(), ('0.0.0.0', port))
      message, source = sock.recvfrom(4096)

      resp = Packet(message, source)

      for ans in resp.answers:
        response.append(ans.RData)
    
    response = []
    s = Server(0)
    c = threading.Thread(target=client, args=(response,s.port))
    s = threading.Thread(target=server, args=(s,))

    s.start()
    c.start()

    c.join(10)

    assert not c.isAlive()
    assert response == ['\x7f\x00\x00\x01']
