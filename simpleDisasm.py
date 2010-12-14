import sys
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

shell = (
"\x90\x90\x90\x90\x90\xCC\xCC\xCC\xCC"
)

if __name__ == "__main__":
    pid = None
    cmd = ""
    trace = vtrace.getTrace()
    
    d = dis.i386Disasm()
    i = 0
    count = 0
    while count < len(shell):
        try:
            op = trace.makeOpcode(shell, offset=i, va=0)
            print "%14s:\t %s" %(shell[count:count+op.size].encode('hex'), op)
            #print "COUNT: ", count
            #print "OP SIZE: ", op.size
            i += 1
            count += op.size
        except:
            print "ERROR: ", sys.exc_info()[1]
            i += 1
            count += 1
            continue

