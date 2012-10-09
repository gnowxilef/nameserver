import socket
import struct
import bits
import dns

entries = {
  'py.zmbush.com' : {
    'NS' : 'ns.zmbush.com'
  },
  'zabu.py.zmbush.com' : {
    'A' : '0.0.0.0'
  },
  'test.py.zmbush.com' : {
    'A' : '127.0.0.1'
  },
  'test2.py.zmbush.com' : {
    'A' : '255.255.255.255'
  },
  'here.py.zmbush.com' : {
    'A' : '136.152.15.33'
  }
}

serv = dns.Server(15353)
while True:
  p = serv.getRequest()
  print
  print p
  print
  resp = p.makeResponse()

  for question in p.questions:
    a = question.createAnswer(entries)
    if a != None:
      resp.addAnswer(a)
  print
  print resp
  print
  serv.sendResponse(resp)
