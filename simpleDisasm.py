import sys
import simpleAPI as v_api
#VDB_ROOT = "<path-to-VDB>"

sys.path.append(VDB_ROOT)

import pickle
from socket import htonl
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
def load_binary(shellcode, base=None):
    trace = vtrace.getTrace()

    try:
        v_api.disasm(trace, binascii.unhexlify(shellcode))
    except:
        f = open(shellcode, 'rb')
        tmp = f.read()
        f.close()
        
        shell = binascii.unhexlify(tmp)
        v_api.disasm(trace, shell)

######################################################################
def main(argv):
    if len(argv) != 2:
        print "Usage: %s <shell code>" % sys.argv[0]
        sys.exit(1)

    shellcode = sys.argv[1]

    load_binary(shellcode)

if __name__ == "__main__":
    main(sys.argv)
    sys.exit(0)
