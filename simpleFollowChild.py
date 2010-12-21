import sys
import vtrace
import vdb
import envi
from envi.archs.i386 import *
import vtrace.envitools as envitools
import PE as PE

import pylab as pylab
import vdb.recon as v_recon
import vdb.recon.sniper as v_sniper
import vdb.stalker as v_stalker

class CustomNotifier(vtrace.Notifier):
    # Event is one of the vtrace.NOTIFY_* things listed under vtrace

    def notify(self, event, trace):
        #print "Got event: %d from pid %d" % (event, trace.getPid())
        #print "PID %d thread(%d) got" % (trace.getPid(), trace.getMeta("ThreadId"))

        # get the details
        #details = trace.getMeta('Win32Event')
        #print "DETAILS: ", details

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

                addr = getOEP(trace, "pwnables100")
                memMap = trace.getMemoryMap(addr)
                begin = memMap[0]
                size = memMap[1]
                trace.protectMemory(begin, size, envi.memory.MM_READ_EXEC)

                win32 = trace.getMeta("Win32Event", None)
                if win32:
                    code = win32["ExceptionCode"]
                    print "Win32 ExceptCode: ", code

        elif event == vtrace.NOTIFY_BREAK:
            print "vtrace.NOTIFY_BREAK", printableEIP(trace)
            print "BESTNAME: ", trace.getSymByAddr(getEIP(trace), exact=False)
            #pass
        elif event == vtrace.NOTIFY_SYSCALL:
            print "vtrace.NOTIFY_SYSCALL"
        elif event == vtrace.NOTIFY_CONTINUE:
            #print "vtrace.NOTIFY_CONTINUE"
            pass
        elif event == vtrace.NOTIFY_EXIT:
            print "vtrace.NOTIFY_EXIT"
            print "ExitCode",trace.getMeta("ExitCode")
        elif event == vtrace.NOTIFY_ATTACH:
            print "vtrace.NOTIFY_ATTACH"
            #pass
        elif event == vtrace.NOTIFY_DETACH:
            print "vtrace.NOTIFY_DETACH"
            #pass
        elif event == vtrace.NOTIFY_LOAD_LIBRARY:
            #print "vtrace.NOTIFY_LOAD_LIBRARY \t", trace.getMeta('LatestLibrary')
            pass
        elif event == vtrace.NOTIFY_UNLOAD_LIBRARY:
            #print "vtrace.NOTIFY_UNLOAD_LIBRARY"
            pass
        elif event == vtrace.NOTIFY_CREATE_THREAD:
            #print "vtrace.NOTIFY_CREATE_THREAD \t", trace.getMeta("ThreadId")
            pass
        elif event == vtrace.NOTIFY_EXIT_THREAD:
            #print "vtrace.NOTIFY_EXIT_THREAD"
            #print "ExitThread",trace.getMeta("ExitThread", -1)
            pass
        elif event == vtrace.NOTIFY_STEP:
            #print "vtrace.NOTIFY_STEP"
            print "BESTNAME: ", trace.getSymByAddr(getEIP(trace), exact=False)
            print "Current Thread: ", trace.getCurrentThread()
            print "THREADS: ", trace.getThreads()
            pass
        else:
            print "vtrace.NOTIFY_WTF_HUH?"

def getEIP(trace):
    eip = trace.getRegister(REG_EIP)
    return eip

def printableEIP(trace):
    return hex(getEIP(trace))

# Only returns the address to the first function found
def findFunc(trace, pattern):
    pattern = pattern.lower()
    libs = trace.getNormalizedLibNames()
    libs.sort()
    for libname in libs:
        for sym in trace.getSymsForFile(libname):
            r = repr(sym)
            if pattern != None:
                if r.lower().find(pattern) == -1:
                     continue
            #print("0x%.8x %s" % (sym.value, r))
            return sym.value

def setBpOnPattern(trace, pattern):
    addr = findFunc(trace, pattern)
    bp = vtrace.Breakpoint(addr)
    trace.addBreakpoint(bp)

def printBp(trace):
    for bp in trace.getBreakpoints():
        print("%s enabled: %s" % (bp, bp.isEnabled()))

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

# This function will change the input variables so that child process
# starts paused.  Then reads the PID of the newly created child process 
# and attaches to it
# NOTE: trace object should be at the _1st_ instruction in CreateProcessA
# for this to function.  Upon return you will be at OEP for child process 
def followCreateProcessA(trace):
    dwAddr = trace.getRegister(REG_ESP)
    #dwAddr -=44#move esp to location of stack from CreateProcessA

    dwAddr +=4#remove eip
    dwAddr +=4#remove lpApplicationName
    dwAddr +=4#remove lpCommandLine
    dwAddr +=4#remove procattrs
    
    dwAddr +=4#remove threadattrs
    dwAddr +=4#remove inheritHandles
    dwCreateFlags=struct.unpack("I",trace.readMemory(dwAddr,4))[0]
    dwCreateFlags|=4
    dwCreateFlags=struct.pack("I",dwCreateFlags)
    try:
        trace.writeMemory(dwCreateFlags,dwAddr)
    except:
        pass

    # Add a breakpoint on the return address from CreateProcessA
    # Run to it and then call afterCreateProcessA
    # This is so the PID variable is populated.

    esp = trace.getRegister(REG_ESP)
    ret = trace.readMemory(esp,4)
    ret2 = struct.unpack("I",ret)[0]
    bp = vtrace.Breakpoint(None, expression=hex(ret2))
    trace.addBreakpoint(bp)
    printBp(trace)

    trace.run()
    esp = trace.getRegister(REG_ESP)

    dwAddr = esp
    dwAddr -=44#move esp to location of stack from CreateProcessA
    dwAddr +=24#move esp to location after some CreateProcessA variables

    dwAddr +=4#remove dwCreationFlags
    dwAddr +=4#remove lpEnvironment
    
    dwAddr +=4#remove lpCurrentDirectory
    dwAddr +=4#remove lsStartupInfo
    # dwAddr points to lpProcessInformation
    #print "dwAddr: ", dwAddr
    procid = trace.readMemory(dwAddr, 4)
    procid = struct.unpack("I", procid)[0]
    procid +=4#remove hProcess
    procid +=4#remove hThread
    # procid points to dwProcessId
    try:
        pid = struct.unpack("I", trace.readMemory(procid, 4))[0]
        print "ProcID: ", pid
        if pid != None:
            #trace.newTrace()
            trace.attach(pid)
            print "ADD TRACE: ", trace.getPid()
    except:
        pass
    
    addr = getOEP(trace, "pwnables100")
    nxMemPerm(trace, addr)


# Change the permissions on the memory map containing addr 
# removing execute permissions.  
# Catch the exception in the notifier, change the permissions
# back and continue running the child process with the debugger attached.
# NOTE: Notifier must be enabled before the call to this function.    
def nxMemPerm(trace, addr):
    memMap = trace.getMemoryMap(addr)
    begin = memMap[0]
    size = memMap[1]
    print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
    print "OEP: ", hex(addr)

    trace.protectMemory(begin, size, envi.memory.MM_NONE)
    print "MEMORY NX SET"
    print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
    trace.run()

#######################################################################
if __name__ == "__main__":
    pid = None
    cmd = "C:\\pwnables100.exe"
    opList = {}
    
    trace = vtrace.getTrace()

    if pid != None:
        trace.attach(pid)
    elif cmd != None:
        trace.execute(cmd)

#######################################################################
# Enable the notifier.  Used later to catch the page execute exception.
    notif = CustomNotifier()
    eve = vtrace.NOTIFY_ALL
    trace.registerNotifier(eve, notif)
#######################################################################
# Set a breakpoint on CreateProcessA and run until it is hit
    pattern = "CreateProcessA()"
    setBpOnPattern(trace, pattern)
    printBp(trace)
    trace.run()

#######################################################################
# Function sets child process to start suspended and attaches to it
# as soon as it returns to userland.
    print "followCreateProcessA"
    followCreateProcessA(trace)

#####################################################################
# Beyond this point the debugger is attached to the child process
# 
    print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
    print "HOLY BREAKPOINT BATMAN!"
    print "EIP: ", printableEIP(trace)
    