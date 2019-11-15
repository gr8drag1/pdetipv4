#!/usr/bin/gawk -f


#-----------------------------------------------------------------------------#
# Copyright 2019 Packet Detectives, Vadim Zakharine and contributors.         #
# License GPLv2+: GNU GPL version 2 or later                                  #
# <http://www.gnu.org/licenses/old-licenses/gpl-2.0.html>                     #
# This is free software; see the source for copying conditions. There is NO   #
# warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. #
#-----------------------------------------------------------------------------#

#-----------------------------------------------------------------------------#
#                                                                             #
# PDetIPv4 auxiliary utility for convert the output of PDetIPv4.py into a     #
# hexdump for Wireshark utility "text2pcap" to covert into libpcap format     #
#                                                                             #
# r1 : Initial release. The IPv4 header assumed to have no prefix bytes       #
#                                                                             #
#-----------------------------------------------------------------------------#

BEGIN {
 for(i = 0; i < 256; i++) {
  x2d[sprintf("%02x", i)] = i
 }
 RS = "\r*\n\r*"
}

# Consider only standard 20 B headers

($3 == "45") {
 ofst = 0
 printf("%04x  02 00 00 00 00 00 02 00 00 00 00 00 08 00", ofst);
 ofst += 14;

 for(i = 3; i <= NF; i++) {
  if((ofst % 16) == 0) {
   printf("  ....\n%04x ", ofst)
  }
  printf(" %s", $i);
  ofst++;
 }

 while((ofst % 16) > 0) {
  printf("   ");
  ofst++;
 }
 print("  ....\n");
}
