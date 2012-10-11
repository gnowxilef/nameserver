import socket
import struct
import bits
import dns
import sys
from optparse import OptionParser

if __name__ == "__main__":
  parser = OptionParser()

  parser.add_option("-f", "--file", dest="filename", 
                    help="File to load DNS records from [Default: %default]", 
                    metavar="FILE", default="ns.ns", type="string")
  parser.add_option("-p", "--port", dest="port",
                    help="Specify port to listen to [Default: %default]",
                    metavar="PORT", default=53, type="int")
  parser.add_option('-d', '--dump', dest="dump", action="store_true",
                    help="Dump out DNS records and exit",
                    default=False)

  (options, args) = parser.parse_args()

  entries = dns.loadNSFile(options.filename)

  if options.dump:
    for url, data in entries.items():
      for Type, values in data.items():
        if Type == "SOA":
          Start, Manager, serial, refresh, retry, expire, minimum = values[0]
          print url,"\tIN\t",Type,"\t",Start,"\t",Manager," ("
          print serial
          print refresh
          print retry
          print expire
          print minimum, ")"
        for parts in values:
          if len(parts) == 2:
            ttl,name = parts
            print url,"\t",ttl,"\t",Type,"\t",name
    sys.exit(0)

  serv = dns.Server(options.port)
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
