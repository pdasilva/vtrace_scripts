import sys
import simpleAPI as v_api
#VDB_ROOT = "<path-to-VDB>"

sys.path.append(VDB_ROOT)

import vtrace
import vdb
import PE as PE

import envi
import envi.memory as mem
from envi.archs.i386 import *

import vdb.stalker as v_stalker

debug = False

###################################################################
###################################################################
def load_binary(filepath, base=None):
    
    # Get the current trace object from vtrace
    trace = vtrace.getTrace()
    trace.setMode("FastBreak", True)

    # If attempting to attach to a 64 bit process
    # 64 bit python is required.
    trace.execute(filepath)

    # Call a function to set BP on OEP
    oep = v_api.getOEP(trace, filepath)
    print "OEP: %x" % oep

#######################################################################
# Add a breakpoint on CreateProcessA
# Run until the breakpoint   
    pattern = "kernel32.CreateProcessA"
    v_api.setBpOnPattern(trace, pattern)
    trace.run()
    trace = v_api.followCreateProcessA(trace)
##########################################################
    # Stalker
    #addr is here since child process doens't start at oep
    addr = 0x004015ac

    try:
        v_stalker.addStalkerEntry(trace, addr)
    except:
        pass
    print('Added 0x%.8x to Stalker list' % addr)
######################################################################
## Beyond this point the debugger is attached to the child process
##
    trace.setMode("FastBreak", True)
    while trace.isAttached():
        trace.run()
    
    f = file("zTest.stalk", "wb")

    # Prints out the current stalker hits
    # Not currently working.... 
    #print('Current Stalker Hits:')
    for hitva in v_stalker.getStalkerHits(trace):
        print('\t 0x%.8x' % hitva)
        f.write('\t 0x%.8x\n' % hitva)
    f.close()

######################################################################
def main(argv):
    if len(argv) != 2:
        print "Usage: %s <exe bin>" % sys.argv[0]
        sys.exit(1)

    filepath = sys.argv[1]

    load_binary(filepath)

if __name__ == "__main__":
    main(sys.argv)
    sys.exit(0)
