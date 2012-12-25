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
def load_binary(filepath, base=None):
    # Get the current trace object from vtrace
    trace = vtrace.getTrace()

    # If attempting to attach to a 64 bit process
    # 64 bit python is required.
    trace.execute(filepath)

    # Call a function to set BP on OEP
    oep = v_api.getOEP(trace, filepath)

    # Set breakpoint at address
    bp = vtrace.Breakpoint(oep)
    trace.addBreakpoint(bp)

    # Print out all the current breakpoints as well as if they are enabled.
    for bp in trace.getBreakpoints():
        print("%s enabled: %s" % (bp, bp.isEnabled()))

    # Start executing the program until you hit a breakpoint or it ends
    trace.run()
##############################################################
# At this point you are at OEP of the program

    # We know that there is a call 5 instructions in
    # There are ways to programmatically find a call
    for i in range(5):
        trace.stepi()

    # Print the value of EIP as a long and as hex
    print "\n"
    print "EIP: ", trace.getRegister(REG_EIP)
    print "HEX EIP: ", hex(trace.getRegister(REG_EIP))

    # Once you are in the function you can read the value of ESP
    # ESP points to the value of the return address
    print "\n"
    esp = trace.getRegister(REG_ESP)
    retaddr = trace.readMemory(esp, 4)

    # Returns the exact memory locations
    # Just in the WRONG order 
    print "RET: ", retaddr.encode('hex')

    # This returns the address correctly formatted
    print "RET: ", hex(struct.unpack("I",retaddr)[0])

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
