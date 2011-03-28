import sys
import simpleAPI as v_api
#VDB_ROOT = "<path-to-VDB>"

sys.path.append(VDB_ROOT)

import vtrace
import vdb
import PE as PE
from envi.archs.i386 import *
import vdb.stalker as v_stalker

#######################################################################
def load_binary(filepath, pattern, base=None):
    # Get the current trace object from vtrace
    trace = vtrace.getTrace()

    # If attempting to attach to a 64 bit process
    # 64 bit python is required.
    trace.execute(filepath)

    pattern = pattern.lower()

    # Get the list of all library names
    # Iterate over the list of function names for values that match pattern
    libs = trace.getNormalizedLibNames()
    libs.sort()
    for libname in libs:
        for sym in trace.getSymsForFile(libname):
            r = repr(sym)
            if pattern != None:
                if r.lower().find(pattern) == -1:
                     continue
            print("0x%.8x %s" % (sym.value, r))

######################################################################
def main(argv):
    if len(argv) != 3:
        print "Usage: %s <exe bin>" " <pattern>"% sys.argv[0]
        sys.exit(1)

    filepath = sys.argv[1]
    # Pattern is the dll you want to search for function names in
    pattern = sys.argv[2]

    load_binary(filepath, pattern)

if __name__ == "__main__":
    main(sys.argv)
    sys.exit(0)
