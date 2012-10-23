import pytest
import sys
import os
from dns import *
from six import b

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

