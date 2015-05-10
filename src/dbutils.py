#!/usr/bin/python
#Main module of tinypyids

import sys
import os
import binascii
from pysqlite2 import dbapi2 as sqlite

def octet2bin(oct):
  eightbitstr = ''
  for i in reversed(range(8)):
    eightbitstr = eightbitstr + str((oct & (1 << i)) and 1)
  return eightbitstr

def hex2bin(hex):
  bitstr = ''
  for oct in binascii.unhexlify(hex):
    bitstr = bitstr + str(octet2bin(ord(oct)))
  return bitstr

def getethertype(hdr):
  hdrstr = ''
  for i in range(len(hdr)-4, len(hdr)):
    hdrstr = hdrstr + hdr[i]
  return hdrstr

def getbinstr(hdr, i, j):
  binoffstr = ''
  binstr = hex2bin(hdr)
  for n in range(i, j):
    binoffstr = binoffstr + binstr[n]
  return binoffstr

def bin2dec(binstr):
  dec = 0
  for n in range(len(binstr)):
    dec = dec + int(binstr[n]) * (1<<(len(binstr)-n-1))
  return dec

def initializedb(dbfile):
#Connects to database if exists, otherwise creates it
  if os.path.isfile(dbfile):
    print "Connecting to database file: %s" % dbfile
    connection = sqlite.connect(dbfile)
  else:
    print "Creating database file: %s" % dbfile
    connection = sqlite.connect(dbfile)
    cursor = connection.cursor()
    cursor.execute("""CREATE TABLE tbl_pkts (id INTEGER PRIMARY KEY,
                                             eth_src VARCHAR(17),
                                             eth_dest VARCHAR(17),
                                             eth_type VARCHAR(4),
                                             eth_hdrhex VARCHAR(50),
                                             ip_src VARCHAR(15),
                                             ip_dest VARCHAR(15),
                                             ip_hdrhex VARCHAR(150),
                                             ip_hdrlen INTEGER,
                                             ip_pktlen INTEGER,
                                             ip_flags VARCHAR(3),
                                             ip_offset INTEGER,
                                             ip_pktid INTEGER,
                                             ip_ttl INTEGER,
                                             ip_checksum INTEGER,
                                             ip_protocol INTEGER,
                                             arp_op INTEGER,
                                             arp_src VARCHAR(50),
                                             arp_tgt VARCHAR(50),
                                             lyr4_src INTEGER,
                                             lyr4_dest INTEGER,
                                             lyr4_checksum INTEGER,
                                             lyr4_hdrhex VARCHAR(150),
                                             tcp_seq INTEGER,
                                             tcp_ack INTEGER,
                                             tcp_flags VARCHAR(12),
                                             tcp_urg INTEGER,
                                             tcp_window INTEGER,
                                             databytes VARCHAR(5000),
                                             time FLOAT
                                             )""")
  return

def printdb(dbfile, outputfilename):
  savedoutput = sys.stdout #for logging purposes, save stdout to dboutput.txt
  outputfile = open(outputfilename, 'w')
  sys.stdout = outputfile
  connection = sqlite.connect(dbfile)
  cursor = connection.cursor()
  cursor.execute('SELECT * FROM tbl_pkts')
  for i in cursor:
    print '-'*20
    print 'id: ', i[0]
    print 'eth_src: ', i[1]
    print 'eth_dest: ', i[2]
    print 'eth_type: ', i[3]
    print 'eth_hdrhex: ', i[4]
    print 'ip_src: ', i[5]
    print 'ip_dest: ', i[6]
    print 'ip_hdrhex: ', i[7]
    print 'ip_hdrlen: ', i[8]
    print 'ip_pktlen: ', i[9]
    print 'ip_flags: ', i[10]
    print 'ip_offset: ', i[11]
    print 'ip_pktid: ', i[12]
    print 'ip_ttl: ', i[13]
    print 'ip_checksum: ', i[14]
    print 'ip_protocol: ', i[15]
    print 'arp_op: ', i[16]
    print 'arp_src: ', i[17]
    print 'arp_tgt: ', i[18]
    print 'lyr4_src: ', i[19]
    print 'lyr4_dest: ', i[20]
    print 'lyr4_checksum: ', i[21]
    print 'lyr4_hdrhex: ', i[22]
    print 'tcp_seq: ', i[23]
    print 'tcp_ack: ', i[24]
    print 'tcp_flags: ', i[25]
    print 'tcp_urg: ', i[26]
    print 'tcp_window: ', i[27]
    databytes = i[28].decode('hex').decode('utf-8', 'replace')
    print 'databytes: ', databytes.encode('ascii', 'replace')
    print 'time: ', i[29]
    print '-'*20
  outputfile.flush()
  outputfile.close()
  sys.stdout = savedoutput #restore stdout
  return

def parsedb(dbfile):
  connection = sqlite.connect(dbfile)
  cursor = connection.cursor()
  cursor.execute('SELECT * FROM tbl_pkts')
  dbobj_list = []
  for i in cursor:
    dbobj = [i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],
            i[18],i[19],i[20],i[21],i[22],i[23],i[24],i[25],i[26],i[27],i[28].decode('hex'),i[29]]
    dbobj_list.append(dbobj)
  return dbobj_list

def parsecapobj(pkt):
#Parses packet and returns database object
  dbobj = []
  try:
    dbobj.append(pkt[0].source)
    dbobj.append(pkt[0].destination)
    ethertype = getethertype(pkt[0].packet.encode('hex'))
    #must parse ethertype field manually - pycap does not parse correctly - returns little endian when should be big endian
    dbobj.append(ethertype)
    dbobj.append(pkt[0].packet.encode('hex'))
  except AttributeError:
  #if pkt[0].source does not exist, Attribute Error will be raised
  #save raw data to databytes and timestamp to time, set all other fields to -1
    #set Ethernet related fields to -1
    dbobj.append('-1')
    dbobj.append('-1')
    dbobj.append('-1')
    dbobj.append('-1')
    #set IP related fields to -1
    dbobj.append('-1')
    dbobj.append('-1')
    dbobj.append('-1')
    dbobj.append(-1)
    dbobj.append(-1)
    #flags not parsed by pycap, manually parse as binary string
    dbobj.append('-1') #IP flags
    #must parse offset field manually - pycap does not parse correctly - returns a 16-bit value when should be 13-bit
    dbobj.append(-1) #offset
    dbobj.append(-1)
    dbobj.append(-1)
    dbobj.append(-1)
    dbobj.append(-1)
    #set ARP related fields to -1
    dbobj.append(-1)
    dbobj.append('-1')
    dbobj.append('-1')
    #set transport layer fields to -1
    dbobj.append(-1)
    dbobj.append(-1)
    dbobj.append(-1)
    dbobj.append('-1')
    dbobj.append(-1)
    dbobj.append(-1)
    dbobj.append('-1')
    dbobj.append(-1)
    dbobj.append(-1)
    #append raw payload data and timestamp
    dbobj.append(pkt[0]) #payload data
    dbobj.append(pkt[1]) #timestamp
    return dbobj
  else:
    if ethertype == '0800':
      #if IP then append IP related fields, set others to -1
      dbobj.append(pkt[1].source)
      dbobj.append(pkt[1].destination)
      dbobj.append(pkt[1].packet.encode('hex'))
      dbobj.append(pkt[1].headerlength)
      dbobj.append(pkt[1].length)
      #flags not parsed by pycap, manually parse as binary string
      dbobj.append(getbinstr(pkt[1].packet.encode('hex'), 48, 51)) #IP flags
      #must parse offset field manually - pycap does not parse correctly - returns a 16-bit value when should be 13-bit
      dbobj.append(bin2dec(getbinstr(pkt[1].packet.encode('hex'), 51, 64))) #offset
      dbobj.append(pkt[1].id)
      dbobj.append(pkt[1].timetolive)
      dbobj.append(pkt[1].checksum)
      dbobj.append(pkt[1].protocol)
      #set -1 for the ARP related fields
      dbobj.append(-1)
      dbobj.append('-1')
      dbobj.append('-1')
      if(pkt[1].protocol == 6):
        #if TCP set all TCP related fields
        dbobj.append(pkt[2].sourceport)
        dbobj.append(pkt[2].destinationport)
        dbobj.append(pkt[2].checksum)
        dbobj.append(pkt[2].packet.encode('hex'))
        dbobj.append(pkt[2].sequence)
        dbobj.append(pkt[2].acknowledge)
        #flags represented as integer by pycap, parse them manually as bit string
        dbobj.append(getbinstr(pkt[2].packet.encode('hex'), 100, 112)) #TCP flags
        dbobj.append(pkt[2].urgent)
        dbobj.append(pkt[2].window)
        #append raw payload data and timestamp
        dbobj.append(pkt[3]) #payload data
        dbobj.append(pkt[4]) #timestamp
      elif(pkt[1].protocol == 17):
        #if UDP set all UDP related fields and all others to -1
        dbobj.append(pkt[2].sourceport)
        dbobj.append(pkt[2].destinationport)
        dbobj.append(pkt[2].checksum)
        dbobj.append(pkt[2].packet.encode('hex'))
        dbobj.append(-1)
        dbobj.append(-1)
        dbobj.append('-1')
        dbobj.append(-1)
        dbobj.append(-1)
        #append raw payload data and timestamp
        dbobj.append(pkt[3]) #payload data
        dbobj.append(pkt[4]) #timestamp
      else:
        dbobj.append(-1)
        dbobj.append(-1)
        dbobj.append(-1)
        dbobj.append('-1')
        dbobj.append(-1)
        dbobj.append(-1)
        dbobj.append('-1')
        dbobj.append(-1)
        dbobj.append(-1)
        #append raw payload data and timestamp
        dbobj.append(pkt[2]) #payload data
        dbobj.append(pkt[3]) #timestamp
      return dbobj
    elif ethertype == '0806':
      #if ARP append ARP related fields, set others to -1
      dbobj.append(pkt[1].sourceprotocol)
      dbobj.append(pkt[1].targetprotocol)
      dbobj.append(pkt[1].packet.encode('hex'))
      #set all IP-specific fields to -1
      dbobj.append(-1)
      dbobj.append(-1)
      #flags not parsed by pycap, manually parse as binary string
      dbobj.append('-1') #IP flags
      #must parse offset field manually - pycap does not parse correctly - returns a 16-bit value when should be 13-bit
      dbobj.append(-1) #offset
      dbobj.append(-1)
      dbobj.append(-1)
      dbobj.append(-1)
      dbobj.append(-1)
      #set ARP related fields
      dbobj.append(pkt[1].operation)
      dbobj.append(pkt[1].sourcehardware)
      dbobj.append(pkt[1].targethardware)
      #set transport layer fields to -1
      dbobj.append(-1)
      dbobj.append(-1)
      dbobj.append(-1)
      dbobj.append('-1')
      dbobj.append(-1)
      dbobj.append(-1)
      dbobj.append('-1')
      dbobj.append(-1)
      dbobj.append(-1)
      #append raw payload data and timestamp
      dbobj.append(pkt[2]) #payload data
      dbobj.append(pkt[3]) #timestamp
      return dbobj
    else:
      #ethertype is not ARP or IPv4
      #save raw data to databytes and timestamp to time, set all other fields to -1
      #set IP related fields to -1
      dbobj.append('-1')
      dbobj.append('-1')
      dbobj.append('-1')
      dbobj.append(-1)
      dbobj.append(-1)
      #flags not parsed by pycap, manually parse as binary string
      dbobj.append('-1') #IP flags
      #must parse offset field manually - pycap does not parse correctly - returns a 16-bit value when should be 13-bit
      dbobj.append(-1) #offset
      dbobj.append(-1)
      dbobj.append(-1)
      dbobj.append(-1)
      dbobj.append(-1)
      #set ARP related fields to -1
      dbobj.append(-1)
      dbobj.append('-1')
      dbobj.append('-1')
      #set transport layer fields to -1
      dbobj.append(-1)
      dbobj.append(-1)
      dbobj.append(-1)
      dbobj.append('-1')
      dbobj.append(-1)
      dbobj.append(-1)
      dbobj.append('-1')
      dbobj.append(-1)
      dbobj.append(-1)
      #append raw payload data and timestamp
      dbobj.append(pkt[1]) #payload data
      dbobj.append(pkt[2]) #timestamp
      return dbobj

def parsecapture(pcap, j):
#Parses capture and returns database object list
  dbobj_list = []
  len = 0
  #parse this portion of the capture
  while len < j:
    packet = pcap.next()
    if packet is not None:
      dbobj_list.append(parsecapobj(packet))
      len = len + 1
    else:
      return dbobj_list
  return dbobj_list

def insert(dbobj_list, dbfile):
#Iterates through all objects in the list and inserts them into database
  connection = sqlite.connect(dbfile)
  cursor = connection.cursor()
  for i in range(0, len(dbobj_list)):
    cursor.execute("""INSERT INTO tbl_pkts VALUES (null,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?,
                                                  ?)"""
                                                  ,(dbobj_list[i][0],
                                                  dbobj_list[i][1],
                                                  dbobj_list[i][2],
                                                  dbobj_list[i][3],
                                                  dbobj_list[i][4],
                                                  dbobj_list[i][5],
                                                  dbobj_list[i][6],
                                                  dbobj_list[i][7],
                                                  dbobj_list[i][8],
                                                  dbobj_list[i][9],
                                                  dbobj_list[i][10],
                                                  dbobj_list[i][11],
                                                  dbobj_list[i][12],
                                                  dbobj_list[i][13],
                                                  dbobj_list[i][14],
                                                  dbobj_list[i][15],
                                                  dbobj_list[i][16],
                                                  dbobj_list[i][17],
                                                  dbobj_list[i][18],
                                                  dbobj_list[i][19],
                                                  dbobj_list[i][20],
                                                  dbobj_list[i][21],
                                                  dbobj_list[i][22],
                                                  dbobj_list[i][23],
                                                  dbobj_list[i][24],
                                                  dbobj_list[i][25],
                                                  dbobj_list[i][26],
                                                  dbobj_list[i][27].encode('hex'),
                                                  dbobj_list[i][28]
                                                  ))
    connection.commit()
  return
