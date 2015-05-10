#!/usr/bin/python
#Main module of tinypyids

import sys
import os
import pycap.capture
import dbutils
#import detect
from optparse import OptionParser

INC_PARSE = 100
#Parse dbobj_list into increments of above qty

def analyze(dbobj_list):
  #Detect attacks and print output to screen/file
  #detect.synflood(dbobj_list)
  #detect.arpflood(dbobj_list)
  print ("Analyzing %s packets..." % str(len(dbobj_list)))
  return

def extract(dbfile):
  #Extract current database into list and analyze it
  dbobj_list = dbutils.parsedb(dbfile) #Parse entire DB into dbobj_list
  analyze(dbobj_list)
  return

def load(pcapfile, dbfile, analyzing):
  #Load pcapfile into database, analyze if analyzing
  if os.path.isfile(pcapfile):
    print "Loading database from file: %s" % pcapfile
  else:
    print "File: %s does not exist" % pcapfile
    return
  pcap = pycap.capture.capture()
  pcap = pcap.fromFile(pcapfile)
  while True:
    dbobj_list = dbutils.parsecapture(pcap, INC_PARSE)
    #Parse capture from next packetID to end of section
    if len(dbobj_list) == 0: #if end of file, break loop
      break
    #if analyzing, analyze
    if analyzing:
      analyze(dbobj_list)
    dbutils.insert(dbobj_list, dbfile) #insert parsed packets into database
  return

def capture(interface, dbfile, analyzing):
  #Load captured packets into database, analyze if analyzing
  if interface is not None: #if interface is specified, capture it, else capture default
    pcap = pycap.capture.capture(device=interface)
  else:
    pcap = pycap.capture.capture();
  print "Starting packet capture on interface: %s" % pcap.device
  print "Press CNTL + C to stop..."
  while True:
    dbobj_list = dbutils.parsecapture(pcap, INC_PARSE)
    #Parse capture from next packetID to end of section
    #if analyzing, analyze
    if analyzing:
      analyze(dbobj_list)
    dbutils.insert(dbobj_list, dbfile)  #insert parsed packets into database
  return

def main(argv=None):
  #Main function of tinypyids
  if argv is None:
    argv = sys.argv
  if len(sys.argv) == 1:
    print ("%s: an option should be specified" % sys.argv[0])
    print ("Try '%s -h' or '%s --help' for more information" % (sys.argv[0], sys.argv[0]))
    sys.exit(2)
  parser = OptionParser()
  usage = "usage: %prog [-acp] [-l pcapfile] [-i interface] [-d dbfile] [-f textfile]"
  parser = OptionParser(usage=usage)
  parser.add_option("-l", "--load", action="store", type="string", dest="pcap_file", help="loads libpcap dump file into database")
  parser.add_option("-a", "--analyze", action="store_true", dest="analyze", help="analyzes DB contents & captured packets for malicious activity")
  parser.add_option("-c", "--capture", action="store_true", dest="capture", help="captures packets and adds them to database")
  parser.add_option("-i", "--interface", action="store",type="string", dest="interface", help="specifies particular interface for packet capture")
  parser.add_option("-d", "--database", action="store", type="string", dest="db_file", default="output.db", help="specifies particular SQLite database or creates database if doesn't exist")
  parser.add_option("-p", "--print", action="store_true", dest="printDB", help="print database contents to file")
  parser.add_option("-f", "--file", action="store", type="string", dest="outputfile", default="output.txt", help="specifies particular output file for writing output")
  (options, args) = parser.parse_args()
  dbutils.initializedb(options.db_file) #If DB doesn't exist, create it
  #If analyzing, then extract existing database file and analyze it
  if options.analyze:
    extract(options.db_file)
  #If a pcap file is specified then load it
  if options.pcap_file is not None:
    load(options.pcap_file, options.db_file, options.analyze)
    print "Database load complete"
  #If print is specified then print DB contents
  if options.printDB:
    dbutils.printdb(options.db_file, options.outputfile)
    print ("Database output sent to: %s" % options.outputfile)
  #If capture is specified then begin packet capture
  if options.capture:
    capture(options.interface, options.db_file, options.analyze)

if __name__ == "__main__":
    sys.exit(main())


