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
 print("PDetIPv4-text2pcap - Covert the output of PDetIPv4 to format understood by text2pcap") >> "/dev/stderr"
 print("Syntax:") >> "/dev/stderr"
 print(" pdetipv4-text2pcap [-v l2prefix=#] [-v l2hlen=#] <infile>") >> "/dev/stderr"
 print("") >> "/dev/stderr"
 if(l2prefix == "") {
  print("\"l2prefix\" value not set, assumong 0") >> "/dev/stderr"
  prefix = 0
 }
 else {
  l2prefix = int(l2prefix)
  print("\"l2prefix\" set to", l2prefix) >> "/dev/stderr"
 }
 if(l2hlen == "") {
  print("\"l2hlen\" not set, assuming 14") >> "/dev/stderr"
  l2len = 14
 }
 else {
  l2len = int(l2len);
  print("\"l2len\" set to", l2len) >> "/dev/stderr"
 }
 if(l2prefix > l2len) {
  print("Error: l2prefix=" l2prefix, "longer than l2len=" l2len) >> "/dev/stderr"
  exit(65)
 }
 for(i = 0; i < 256; i++) {
  x2d[sprintf("%02x", i)] = i
 }
 RS = "\r*\n\r*"
}


{
 ofst = 0
 if($(3 + l2prefix) == "45") {
# Consider only standard 20 B headers
  printf("%04x ", ofst);
  if(l2prefix < l2len) {
   printf(" 02");
   ofst++;
  }
  if((l2prefix + 7) < l2len) {
   printf(" 00 00 00 00 00 02");
   ofst += 6;
  }
  while((l2prefix + ofst) < (l2len - 2)) {
   if((ofst % 16) == 0) {
    printf("  ....\n%04x ", ofst)
   }
   printf(" 00");
   ofst++;
  }
  if(l2prefix == 0) {
   if((ofst % 16) == 0) {
    printf("  ....\n%04x ", ofst)
   }
   printf(" 08");
   ofst++;
   if((ofst % 16) == 0) {
    printf("  ....\n%04x ", ofst)
   }
   printf(" 00");
   ofst++;
  }
  else {
   while((l2prefix + i) < (l2len - 2)) {
    if((ofst % 16) == 0) {
     printf("  ....\n%04x ", ofst)
    }
    printf(" 00");
    ofst++;
   }
   i++
  }
  for(i = 3; i <= NF; i++) {
   if((ofst % 16) == 0) {
    printf("  ....\n%04x ", ofst)
   }
   printf(" %s", $i);
   ofst++;
  }
 }
 while((ofst % 16) > 0) {
  printf("   ");
  ofst++;
 }
 print("  ....\n");
}
