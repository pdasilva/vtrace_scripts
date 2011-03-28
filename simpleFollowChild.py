import sys
import simpleAPI as v_api
#VDB_ROOT = "<path-to-VDB>"

sys.path.append(VDB_ROOT)

import vtrace
import vdb

import envi
from envi.archs.i386 import *
import vtrace.envitools as envitools
import PE as PE

import vdb.recon as v_recon
import vdb.recon.sniper as v_sniper
import vdb.stalker as v_stalker

class CustomNotifier(vtrace.Notifier):
    # Event is one of the vtrace.NOTIFY_* things listed under vtrace

    def notify(self, event, trace):
        if event == vtrace.NOTIFY_ALL:
            print "WTF, how did we get a vtrace.NOTIFY_ALL event?!?!"

        elif event == vtrace.NOTIFY_SIGNAL:
            print "vtrace.NOTIFY_SIGNAL"
            print "PendingSignal",trace.getMeta("PendingSignal")
            print "PendingException",trace.getMeta("PendingException")
            if trace.getMeta("Platform") == "Windows":
                win32event = trace.getMeta("Win32Event")
                #print repr(win32event)
                print "ExceptionAddress: %(ExceptionAddress)x" % win32event

                addr = v_api.getOEP(trace, "pwnables100")
                memMap = trace.getMemoryMap(addr)
                begin = memMap[0]
                size = memMap[1]
                trace.protectMemory(begin, size, envi.memory.MM_READ_EXEC)

                win32 = trace.getMeta("Win32Event", None)
                if win32:
                    code = win32["ExceptionCode"]
                    print "Win32 ExceptCode: ", code

        elif event == vtrace.NOTIFY_BREAK:
            print "vtrace.NOTIFY_BREAK", v_api.printableEIP(trace)
            #print "BESTNAME: ", trace.getSymByAddr(v_api.getEIP(trace), exact=False)
            #pass
        elif event == vtrace.NOTIFY_EXIT:
            print "vtrace.NOTIFY_EXIT"
            print "ExitCode",trace.getMeta("ExitCode")
        elif event == vtrace.NOTIFY_ATTACH:
            print "vtrace.NOTIFY_ATTACH"
            #pass
        elif event == vtrace.NOTIFY_DETACH:
            print "vtrace.NOTIFY_DETACH"
            #pass
        elif event == vtrace.NOTIFY_STEP:
            #print "vtrace.NOTIFY_STEP"
            # print "BESTNAME: ", trace.getSymByAddr(getEIP(trace), exact=False)
            # print "Current Thread: ", trace.getCurrentThread()
            # print "THREADS: ", trace.getThreads()
            pass
        else:
            pass


#######################################################################
def load_binary(filepath, base=None):
    opList = {}
    trace = vtrace.getTrace()

    trace.execute(filepath)
#######################################################################
# Enable the notifier.  Used later to catch the page execute exception.
    notif = CustomNotifier()
    eve = vtrace.NOTIFY_ALL
    trace.registerNotifier(eve, notif)
#######################################################################
# Set a breakpoint on CreateProcessA and run until it is hit
    pattern = "CreateProcessA()"
    v_api.setBpOnPattern(trace, pattern)
    v_api.printBp(trace)
    trace.run()

#######################################################################
# Functions sets child process to start suspended and attaches to it
# as soon as it returns to userland by setting the Entry Point page
# as non executable and catching the exception that is thrown.
    print "followCreateProcessA"
    v_api.followCreateProcessA(trace)
    
    addr = v_api.getOEP(trace, "pwnables100")
    v_api.nxMemPerm(trace, addr)
#####################################################################
# Beyond this point the debugger is attached to the child process
# 
    print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
    print "HOLY BREAKPOINT BATMAN!"
    print "EIP: ", v_api.printableEIP(trace)

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
