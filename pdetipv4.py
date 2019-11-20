#!/usr/bin/env python3

#-----------------------------------------------------------------------------#
# Copyright 2019 Packet Detectives, Vadim Zakharine and contributors.         #
# License GPLv2+: GNU GPL version 2 or later                                  #
# <http://www.gnu.org/licenses/old-licenses/gpl-2.0.html>                     #
# This is free software; see the source for copying conditions. There is NO   #
# warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. #
#-----------------------------------------------------------------------------#

#-----------------------------------------------------------------------------#
# PDETIPv4 Utility for detecting IPv4 packet headers in dump files            #
#                                                                             #
# r1 : Initial release                                                        #
# r2 : CLI arguement order changed to allow multiple files processing         #
#                                                                             #
#-----------------------------------------------------------------------------#

from os import path
import sys

def main() :
 """
 PDetIPv4 - utility for detecting IPv4 packet headers in a file

 Positional parameters
 ---------------------
  <#bytes_before> <#bytes_after> <infile> [infiles]

  <#bytes_before> : integer
   number of bytes in the file before the header to include in the output

  <#bytes_after> : integer
  number of bytes in the file after the header

  <infile> [infiles] : string
  file name(s)

 Returns
 -------
  exit code
  stdout

  Exit code
   64 in case of syntax error
   No error code returned in case of file open error [because more than one file may be processed]

  StdOut
   offset in the file, byte values

   Offset       Byte values
   0x006d88d9 : 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 32

 Raises
 ------
 None
 """
 print("PDetIPv4 - utility for detecting IPv4 packet headers in a file")
 if len(sys.argv) < 4 :
  print("Syntax:\n {} <#bytes_before> <#bytes_after> <infile> [infiles]".format(path.basename(sys.argv[0])), file = sys.stderr)
  sys.exit(64)
 else :
  j = 3
  while j < len(sys.argv):
   try:
    infile = open(sys.argv[j], "rb")
    print("Scanning \"{}\"...".format(sys.argv[j]), file = sys.stderr)
    bofset = infile.tell()
    bufval = infile.read(1)
    while bufval :
     bufnum = int.from_bytes(bufval, byteorder="big")
     if ((bufnum & 0xf0) == 0x40) and ((bufnum & 0x0f) >= 3) :
#     The header is ver. 4 and at least 12 B to include the checksum
      bufnum = (bufnum & 0x0f) * 4 - 1
      bufval += infile.read(bufnum)
      if len(bufval) <= bufnum :
#      The remainder of the file is smaller than the potential header
       if len(bufval) > 12 :
        infile.seek(bofset + 1, 0)
       else :
        break
      else :
       chksm = 0
       i = 0
       while i < bufnum :
        chksm += int.from_bytes(bufval[i:i+2], byteorder="big")
        while chksm > 0xffff :
         chksm -= 0xffff
        i += 2
       if(chksm == 0xffff) :
        if int(sys.argv[1]) > 0 :
         if int(sys.argv[1]) < bofset :
          print("0x{:08x}".format(bofset - int(sys.argv[1])), end = " :")
          infile.seek(bofset - int(sys.argv[1]), 0)
          i = 0
          while i < int(sys.argv[1]) :
           print(" {:02x}".format(int.from_bytes(infile.read(1), byteorder="big")), end = "")
           i += 1
         else :
          print("0x{:08x}".format(0), end = ":")
          infile.seek(0, 0)
          i = bofset
          while i < int(sys.argv[1]) :
           print(" {:02x}".format(int.from_bytes(infile.read(1), byteorder="big")), end = "")
           i += 1
        else :
         print("0x{:08x}".format(bofset), end = " :")
        for i in bufval :
         print(" {:02x}".format(i), end = "")
        if int(sys.argv[2]) > 0 :
         infile.seek(bofset + bufnum + 1, 0)
         i = int(sys.argv[2]) if int.from_bytes(bufval[2:4], byteorder="big") > int(sys.argv[2]) else int.from_bytes(bufval[2:4], byteorder="big")
         chksm = infile.read(1)
         while (i > 0) and chksm :
          print(" {:02x}".format(int.from_bytes(chksm, byteorder="big")), end = "")
          i -= 1
          chksm = infile.read(1)
        print("")
#      else :
#       print("\n-")
       infile.seek(bofset + 1, 0)
     bofset = infile.tell()
     bufval = infile.read(1)
    infile.close()
    print("\"{}\" scanning done".format(path.basename(sys.argv[j])), file = sys.stderr)
   except Exception as i:
    print("Error opening \"", sys.argv[j], "\": ", i.args[1], file = sys.stderr)
   j += 1
 sys.exit(0)


if __name__ == "__main__" : main()
