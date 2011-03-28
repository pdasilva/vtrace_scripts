import sys
import simpleAPI as v_api
#VDB_ROOT = "<path-to-VDB>"

sys.path.append(VDB_ROOT)

import vtrace
import vdb
import PE as PE
from envi.archs.i386 import *

# The following MUST be done otherwise windows catches the stopped program
# in a horrible attempt to "help". 
# Go to the following registry location and change the value data to 1.
# HKEY_CURRENT_USER\Software\ Microsoft\Windows\Windows Error Reporting\DontShowUI

#######################################################################
def load_binary(filepath, base=None):
    # Get the current trace object from vtrace
    trace = vtrace.getTrace()

    # If attempting to attach to a 64 bit process
    # 64 bit python is required.
    trace.execute(filepath)

    oep = v_api.getOEP(trace, filepath)

    # Set breakpoint at address
    bp = vtrace.Breakpoint(oep)
    trace.addBreakpoint(bp)

    # Print out all the current breakpoints as well as if they are enabled.
    for bp in trace.getBreakpoints():
        print("%s enabled: %s" % (bp, bp.isEnabled()))

    # Start executing the program until you hit a breakpoint or it ends
    trace.run()

    print "Holy BreakPoint Batman!"

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
