import pytest
import sys
from dns import *

def b(s):
  if sys.version_info[0] == 3:
    return s.encode('latin-1')
  else:
    return s

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
    assert q.readFrom(rawq + 'extra') == 'extra'
    assert q.pack() == rawq
