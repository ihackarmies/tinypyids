=================
 Tiny Python IDS 
=================

:Author: Alan Bairley
:Contact: alan.bairley@gmail.com

This module provides the ability to capture and parse packets from network
interfaces and load them into a SQLite database.  Database export to human-readable
text is also supported.  It dissects commonly found structures in network packets
such as Ethernet, IP_, ARP_, TCP_, UDP_, and ICMP_ headers.

Supported Platforms
-------------------

``tinypyids`` should work on any platform that supports libpcap_, libnet_ and
Python_.  It currently requires Python 2.5 or higher, and has been tested on
Python 2.5 and 2.7.  If you find any bugs please feel free to report them to the
author's contact email listed above.

Required Packages
-----------------
``tinypyids`` depends upon the following Python packages:

	1. pycap-0.1.6 (included in tinypyids.tar.gz at ~/tinypyids/Required_packages/pycap-0.1.6/)
		:Author: Mark Rowe
		:Web site: http://pycap.sourceforge.net
		:Project page: http://sourceforge.net/projects/pycap/
		
	2. pysqlite-2.6.3 (included in tinypyids.tar.gz at ~/tinypyids/Required_packages/pysqlite-2.6.3/)
		:Author: Gerhard Haering
		:Home Page: http://pysqlite.googlecode.com/

To Do 
-----

Packet analysis is currently a work in progress.  As of this writing, if the `analyze` 
option is passed to ``tinypyids``, the program output will appear to indicate packet 
analysis by displaying the number of packets analyzed in real-time.  However, please 
realize that no packet analysis is actually being performed.  The output is simply 
a placeholder for the `detect` module, which will continue to be developed in future
versions of ``tinypyids``.  Ultimately, the endstate of the `detect` module is the 
implementation of a comprehensive set of IDS rules that are applied against each packet 
in real-time.

Installation / Execution
------------------------

``tinypyids`` does not require installation.  After extracting the included tarball/gzip 
archive, navigate to ~/tinypyids/src/ (where `~` is the root of the archive) and execute
the following command for usage info and program options:

:: % python tinypyids.py --help

Details
-------
Note that libpcap_ and libnet_ may require superuser access to capture packets.

Example Usage
-------------

:: % python tinypyids.py -c
	//Creates or connects to default database, `output.db`
	//Captures and parses packets on default interface and saves them to default database

:: % python tinypyids.py -p
	//Creates or connects to default database, `output.db`
	//Prints contents of default database to default output file, `output.txt` (human-readable)
	
:: % python tinypyids.py -cd attack1.db
	//Creates or connects to database, `attack1.db`
	//Captures and parses packets on default interface and saves them to `attack1.db`
	
:: % python tinypyids.py -d attack1.db -pf attack1.txt
	//Creates or connects to database, `attack1.db`
	//Prints contents of `attack1.db` to output file, `attack1.txt`
	
:: % python tinypyids.py -l ../Example_captures/pingarp.cap
	//Creates or connects to default database
	//Parses packets from file, `pingarp.cap` and saves them to default database

:: % python tinypyids.py -ci eth1
	//Creates or connects to default database
	//Captures and parses packets on interface, `eth1` and saves them to default database
	

	
