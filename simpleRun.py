import sys
import simpleAPI as v_api
#VDB_ROOT = "<path-to-VDB>"

sys.path.append(VDB_ROOT)

import vtrace
import vdb

#######################################################################
def load_binary(filepath, base=None):
    # Get the current vtrace object
    trace = vtrace.getTrace()

    # If attempting to attach to a 64 bit process
    # 64 bit python is required.
    trace.execute(filepath)

    # Start the program executing
    trace.run()

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
