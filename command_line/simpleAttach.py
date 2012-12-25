import sys
import simpleAPI as v_api
#VDB_ROOT = "<path-to-VDB>"

sys.path.append(VDB_ROOT)

import vtrace
import vdb
from envi.archs.i386 import *


#######################################################################
def load_binary(filePID, base=None):
    
    # Ask for the current trace object so we can play with it
    trace = vtrace.getTrace()

    # If attempting to attach to a 64 bit process
    # 64 bit python is required.
    if pid != None:
        trace.attach(filePID)

    # Start executing the program.  
    # Will not stop until it finishes or is killed    
    trace.run()
######################################################################
def main(argv):
    if len(argv) != 2:
        print "Usage: %s <exe pid>" % sys.argv[0]
        sys.exit(1)

    filePID = sys.argv[1]

    load_binary(filePID)

if __name__ == "__main__":
    main(sys.argv)
    sys.exit(0)