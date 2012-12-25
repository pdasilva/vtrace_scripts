import sys
import simpleAPI as v_api
#VDB_ROOT = "<path-to-VDB>"

sys.path.append(VDB_ROOT)

import pickle
from socket import htonl
from optparse import OptionParser
import vtrace
import vdb
import envi as envi
import envi.archs.i386.disasm as dis
from envi.archs.i386 import *
import vtrace.envitools as envitools
import vtrace.snapshot as vs_snap
import PE as PE
import binascii

#######################################################################
def load_binary(shellcode, fileLoc, base=None):
    trace = vtrace.getTrace()

    if shellcode is not None:
        v_api.disasm(trace, binascii.unhexlify(shellcode))
    
    else:
        print "FILE LOCATION: %s" % fileLoc
        f = open(fileLoc, 'rb')
        tmp = f.read()
        f.close()
        
        shell = binascii.unhexlify(tmp)
        v_api.disasm(trace, shell)
    
    trace.release()

######################################################################
def main(argv):
    parser = OptionParser()
    parser.add_option("-f", "--file", dest="fileLoc", help="input file to be parsed", action='store')
    parser.add_option("-s", "--shellcode", dest="shell", help="shellcode to be parsed", action='store')
    (options, args) = parser.parse_args()
    
    if not options.fileLoc and not options.shell:
        print "A mandatory option is missing\n"
        parser.print_help()
        exit(-1)
    
    if len(argv) != 3:
        parser.print_help()
        sys.exit(1)

    shellcode = options.shell
    fileLoc = options.fileLoc

    load_binary(shellcode, fileLoc)

if __name__ == "__main__":
    main(sys.argv)
    sys.exit(0)
