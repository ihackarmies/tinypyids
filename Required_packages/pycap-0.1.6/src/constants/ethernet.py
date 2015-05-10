
ETHER_ADDR_LEN = 6
ETHER_TYPE_LEN = 2
ETHER_CRC_LEN = 4
HEADER_LENGTH = (ETHER_ADDR_LEN*2+ETHER_TYPE_LEN)

ETHER_MIN_LEN = 64
ETHER_MAX_LEN = 1518

ETHERTYPE_PUP = 0x0200
ETHERTYPE_IP = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_REVARP = 0x8035
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_IPV6 = 0x86dd
ETHERTYPE_LOOPBACK = 0x9000

ETHERTYPE_TRAIL = 0x1000
ETHERTYPE_NTRAILER = 16


