import sys
import simpleAPI as v_api
#VDB_ROOT = "<path-to-VDB>"

sys.path.append(VDB_ROOT)

import vtrace
import vdb

import envi
import envi.memory as mem
from envi.archs.i386 import *

import vtrace.envitools as envitools

import PE
import vstruct

import vdb.recon as v_recon
import vdb.recon.sniper as v_sniper
import vdb.stalker as v_stalker

debug = True
###################################################################

class CustomNotifier(vtrace.Notifier):
    def notify(self, event, trace):
        if event == vtrace.NOTIFY_SIGNAL:
            print "vtrace.NOTIFY_SIGNAL"
            print "PendingSignal",trace.getMeta("PendingSignal")
            print "PendingException",trace.getMeta("PendingException")
            if trace.getMeta("Platform") == "Windows":
                win32event = trace.getMeta("Win32Event")
                #print repr(win32event)
                print "ExceptionAddress: %(ExceptionAddress)x" % win32event

                addr = getOEP(trace, "pwnables100")
                memMap = trace.getMemoryMap(addr)
                begin = memMap[0]
                size = memMap[1]
                trace.protectMemory(begin, size, envi.memory.MM_READ_EXEC)

                win32 = trace.getMeta("Win32Event", None)
                if win32:
                    code = win32["ExceptionCode"]
                    print "Win32 ExceptCode: ", code
        else:
            print "vtrace.NOTIFY_WTF_HUH?"

#######################################################################
def load_binary(filepath, base=None):
    
    trace = vtrace.getTrace()
    trace.execute(filepath)
#######################################################################
    # Call a function to set BP on OEP
    oep = v_api.getOEP(trace, filepath)

    # Set breakpoint at address
    bp = vtrace.Breakpoint(oep)
    trace.addBreakpoint(bp)

######################################################################
    # Start executing the program until you hit a breakpoint or it ends
    trace.run()
#######################################################################
    # Get the list of imported functions to compare against
    importTable = v_api.printIAT(trace, filepath, debug)

#######################################################################
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
