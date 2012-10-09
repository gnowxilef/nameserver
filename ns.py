import socket
import struct
import bits
import dns

entries = dns.loadNSFile('ns.ns')

serv = dns.Server(53)
while True:
  p = serv.getRequest()
  print
  print p
  print
  resp = p.makeResponse()

  for question in p.questions:
    answers = question.createAnswers(entries)
    for a in answers:
      resp.addAnswer(a)
  print
  print resp
  print
  serv.sendResponse(resp)
