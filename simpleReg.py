import sys
import simpleAPI as v_api
#VDB_ROOT = "<path-to-VDB>"

sys.path.append(VDB_ROOT)

import vtrace
import vdb
import PE as PE
from envi.archs.i386 import *

#######################################################################
def load_binary(filepath, base=None):
    # Get the current trace object from vtrace
    trace = vtrace.getTrace()
    trace.execute(filepath)
######################################################################
    # Call a function to set BP on OEP
    oep = v_api.getOEP(trace, filepath)

    # Set breakpoint at address
    bp = vtrace.Breakpoint(oep)
    trace.addBreakpoint(bp)

    # Print out all the current breakpoints as well as if they are enabled.
    for bp in trace.getBreakpoints():
        print("%s enabled: %s" % (bp, bp.isEnabled()))
######################################################################
    # Start executing the program until you hit a breakpoint or it ends
    trace.run()
######################################################################
    # print out the value of EIP as a long and as a hex value
    print "\n"
    print "EIP: ", trace.getRegister(REG_EIP)
    print "HEX EIP: ", hex(trace.getRegister(REG_EIP))
    
    # Read the address of EIP
    eip = trace.getRegister(REG_EIP)
    # Read the memory values pointed to by EIP
    s = trace.readMemory(eip,15)
    # Determine the opcode of the memory pointed to by EIP
    op1 = trace.makeOpcode(s, 0, eip)
    print "OP CODE: ", op1

    # print out the value of EAX as a long and as a hex value
    print "\n"
    print "EAX: ", trace.getRegister(REG_EAX)
    print "HEX EAX: ", hex(trace.getRegister(REG_EAX))

    # Print out the value of ESP as a long and as a hex value
    print "\n"
    print "ESP: ", trace.getRegister(REG_ESP)
    print "HEX ESP: ", hex(trace.getRegister(REG_ESP))

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
