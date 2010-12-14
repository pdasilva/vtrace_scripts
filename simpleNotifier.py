import sys
import vtrace
import vdb
import PE as PE
from envi.archs.i386 import *
import vdb.stalker as v_stalker

class CustomNotifier(vtrace.Notifier):
    # Event is one of the vtrace.NOTIFY_* things listed under vtrace

    def notify(self, event, trace):
        #print "Got event: %d from pid %d" % (event, trace.getPid())
        #print "PID %d thread(%d) got" % (trace.getPid(), trace.getMeta("ThreadId"))

        if event == vtrace.NOTIFY_ALL:
            print "WTF, how did we get a vtrace.NOTIFY_ALL event?!?!"

        elif event == vtrace.NOTIFY_SIGNAL:
            print "vtrace.NOTIFY_SIGNAL"
            print "PendingSignal",trace.getMeta("PendingSignal")
            print "PendingException",trace.getMeta("PendingException")
            if trace.getMeta("Platform") == "Windows":
                print repr(trace.getMeta("Win32Event"))
                print vdb.getSignal(trace.getMeta("PendingSignal"))
                win32 = self.getMeta("Win32Event", None)
                if win32:
                    code = win32["ExceptionCode"]
                    print "Win32 ExceptCode: ", code

        elif event == vtrace.NOTIFY_BREAK:
            print "vtrace.NOTIFY_BREAK", printableEIP(trace)
            pass
        elif event == vtrace.NOTIFY_SYSCALL:
            print "vtrace.NOTIFY_SYSCALL"
        elif event == vtrace.NOTIFY_CONTINUE:
            print "vtrace.NOTIFY_CONTINUE"
            pass
        elif event == vtrace.NOTIFY_EXIT:
            print "vtrace.NOTIFY_EXIT"
            print "ExitCode",trace.getMeta("ExitCode")
        elif event == vtrace.NOTIFY_ATTACH:
            print "vtrace.NOTIFY_ATTACH"
            pass
        elif event == vtrace.NOTIFY_DETACH:
            print "vtrace.NOTIFY_DETACH"
            pass
        elif event == vtrace.NOTIFY_LOAD_LIBRARY:
            print "vtrace.NOTIFY_LOAD_LIBRARY \t", trace.getMeta('LatestLibrary')
            pass
        elif event == vtrace.NOTIFY_UNLOAD_LIBRARY:
            print "vtrace.NOTIFY_UNLOAD_LIBRARY"
            pass
        elif event == vtrace.NOTIFY_CREATE_THREAD:
            print "vtrace.NOTIFY_CREATE_THREAD \t", trace.getMeta("ThreadId")
            pass
        elif event == vtrace.NOTIFY_EXIT_THREAD:
            print "vtrace.NOTIFY_EXIT_THREAD"
            print "ExitThread",trace.getMeta("ExitThread", -1)
            pass
        elif event == vtrace.NOTIFY_STEP:
            print "vtrace.NOTIFY_STEP"
            print "BESTNAME: ", trace.getSymByAddr(getEIP(trace), exact=False)
            print "EIP: ", printableEIP(trace)
            print "OP CODE: ", getOpCode(trace, getEIP(trace))
            print "\n"
            pass
        else:
            print "vtrace.NOTIFY_WTF_HUH?"

def getEIP(trace):
    eip = trace.getRegister(REG_EIP)
    return eip

def printableEIP(trace):
    return hex(getEIP(trace))

def getESP(trace):
    esp = trace.getRegister(REG_ESP)
    return esp

def getRET(trace):
    esp = getESP(trace)
    retaddr = trace.readMemory(esp, 4)
    return struct.unpack("I",retaddr)[0]

def getPrintableRET(trace):
    esp = getESP(trace)
    retprt = trace.readMemory(esp, 4)
    return hex(struct.unpack("I",retaddr)[0])

def getOpCode(trace, eip):
    s = trace.readMemory(eip,15)
    op1 = trace.makeOpcode(s, 0, eip)
    return op1

def getOEP(trace, name):
    # Get a dictionary list of all DLL and PE files loaded by this PE 
    bases = trace.getMeta("LibraryBases")

    entryPoint = None
    imageBase = None

    # Iterate over the list of all PE files in memory looking for our specific one
    for libname in trace.getNormalizedLibNames():
        if name in libname:
            # Pulls the library address from trace.getMeta("LibraryBases") dictionary
            base = bases.get(libname.strip(), None) 
            try:
                pobj = PE.peFromMemoryObject(trace, base)
            except Exception, e:
                print('Error: %s (0x%.8x) %s' % (libname, base, e))
                continue

            # Parse the PE NT Headers looking for the variables we need
            t = pobj.IMAGE_NT_HEADERS.tree()
            for attr in t.split('\n'):
                if "AddressOfEntryPoint" in attr:
                    entryPoint = attr.split(': ')[1].split()[0]
                    #print "Address Of Entry Point: ", entryPoint.strip(None)
                    
                if "ImageBase" in attr:
                    imageBase = attr.split(':')[1].split(' ')[1]
                    #print "ImageBase: ", imageBase.strip(None)

            # Parse the PE sections for variables in the .text section
            for s in pobj.getSections():
                if s.Name.split("\x00", 1)[0] == '.text':
                    for sec in s.tree().split('\n'):
                        if "VirtualSize" in sec:
                            virtualSize = sec.split(': ')[1].split()[0]
                            #print "VirtualSize: ", virtualSize
                        if "VirtualAddress" in sec:
                            virtualAddress = sec.split(': ')[1].split()[0]
                            #print "VirtualAddress: ", virtualAddress
    
    # Original Entry Point is calculated as:
    # Entry Point + Image Base
    if entryPoint and imageBase:
        OEP = int(entryPoint, 0) + int(imageBase, 0)
        return OEP
    else:
        return None


if __name__ == "__main__":
    pid = None
    cmd = "C:\\pwnables100.exe"
    
    # Get the current trace object from vtrace
    trace = vtrace.getTrace()

    # If attempting to attach to a 64 bit process
    # 64 bit python is required.
    if pid != None:
        trace.attach(pid)
    elif cmd != None:
        trace.execute(cmd)
###############################################################
    # The notifier class we want to register
    notif = CustomNotifier()
    # The list of events we want the notifier to handle
    eve = vtrace.NOTIFY_ALL
    # Tell our vtrace object that we want to capture all events with CustomNotifier
    trace.registerNotifier(eve, notif)
###############################################################
    
    # Call a function to set BP on OEP
    oep = getOEP(trace, "pwnables100")

    # Set breakpoint at address
    bp = vtrace.Breakpoint(oep)
    trace.addBreakpoint(bp)

    # Start executing the program until you hit a breakpoint or it ends
    trace.run()
#################################################################

    # Step 5 times into the program
    for i in range(5):
        trace.stepi()

    # Deregister our notifier
    trace.deregisterNotifier(eve, notif)

