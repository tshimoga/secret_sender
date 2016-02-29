#!/usr/bin/python
import sys
from scapy.all import *

if len(sys.argv) < 5:
    exit()
ipAddress = sys.argv[1]
interface = sys.argv[2]
transProtoType = sys.argv[3]
if len(sys.argv)==5:
    message = sys.argv[4] 
else:
    message = sys.argv[4] + " " + sys.argv[5]
nwPacket = IP()
nwPacket.setfieldval('dst',ipAddress)
i=0

if transProtoType== '0':
    transProto = ICMP()
elif transProtoType == '1':
    transProto = TCP()
else:
    transProto = UDP()

for i in range(len(message)):
    x = ord(message[i])
    y = ord('A')
    identifier = (x*256)+y
    nwPacket.setfieldval('id',identifier)
    nwPacket.setfieldval('frag',i)
    send(nwPacket/transProto,iface=interface)
i+=1
nwPacket.setfieldval('id',ord('A'))
nwPacket.setfieldval('frag',4096+i)
send(nwPacket/transProto,iface=interface)


