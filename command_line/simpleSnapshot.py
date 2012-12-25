import sys
import simpleAPI as v_api
#VDB_ROOT = "<path-to-VDB>"

sys.path.append(VDB_ROOT)

import vtrace
import vdb
import PE as PE
from envi.archs.i386 import *
import vdb.stalker as v_stalker
import vtrace.snapshot as vs_snap

#######################################################################
def load_binary(filepath, base=None):
    # Get the current trace object from vtrace
    trace = vtrace.getTrace()

    # If attempting to attach to a 64 bit process
    # 64 bit python is required.
    trace.execute(filepath)
###############################################################
    
    # Call a function to set BP on OEP
    oep = v_api.getOEP(trace, filepath)

    # Set breakpoint at address
    bp = vtrace.Breakpoint(oep)
    trace.addBreakpoint(bp)

    # Start executing the program until you hit a breakpoint or it ends
    trace.run()
#################################################################

    # takes a snapshot of memory
    snap = vs_snap.takeSnapshot(trace)
    # saves it to a file
    snap.saveToFile("zTest.snap")

    # loads a snapshot from a filename
    #snap.loadSnapshot("zTest.snap")
    
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
