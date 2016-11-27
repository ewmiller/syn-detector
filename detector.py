import scapy.all as scapy
import sys

# Goal: read .pcap file packet-by-packet
# for each packet, check if it's a SYN request
# if so, store source IP address in array and make its SYN count 1
# if it appears again, increment its SYN count
# ignore other packets
# once finished, look through the array for any IPs that satisfy the suspicion requirements
# print these to the console

# dictionary to hold known addresses. addr_dict['address'] returns a tuple (a, b)
# where a is SYN packets sent and b is SYN + ACK packets received
addr_dict = {}

# file argument
arg = sys.argv[1]

# hex numbers to identify request types
SYN = 0x02
SYN_ACK = 0x12

# helper methods for processPacket
def count_syn_packet(addr):
  if addr in addr_dict:
    addr_dict[addr] = (addr_dict[addr][0] + 1, addr_dict[addr][1])
  else:
    addr_dict[addr] = (1, 0)

def count_syn_ack_packet(addr):
  if addr in addr_dict:
    addr_dict[addr] = (addr_dict[addr][0], addr_dict[addr][1] + 1)
  else:
    addr_dict[addr] = (0, 1)
    
# lambda function passed to scapy.sniff
def processPacket(packet):
  global SYN
  global SYN_ACK

  if(packet.haslayer("TCP")):
    # grab flags from the packet
    flags = packet["TCP"].flags

    # do a bitwise AND to see which flag is set
    # if SYN or SYN-ACK, respond accordingly
    SYN = 0x02
    SYNACK = 0x12
    if flags & SYN:
      print "SYN detected."
      count_syn_packet(packet["IP"].src)
    elif flags & SYN_ACK:
      print "SYN-ACK detected."
      count_syn_ack_packet(packet["IP"].dst)

def is_suspect(tup):
  try:
    res = tup[0] / tup[1]
  except ZeroDivisionError:
    if tup[0] >= 3:
      return True
    else:
      return False

  if res >= 3:
    return True
  else:
    return False

print "Reading packets from file..."
scapy.sniff(offline=arg, prn=processPacket, lfilter=lambda x: x.haslayer("TCP"))

for k, v in addr_dict.iteritems():
  if is_suspect(v):
    print k

