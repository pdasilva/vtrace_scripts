import sys
import vtrace
import vdb
import envi
from envi.archs.i386 import *
import PE as PE
import vtrace.envitools as envitools
import vtrace.snapshot as vs_snap
import vdb.recon as v_recon
import vdb.recon.sniper as v_sniper
import vdb.stalker as v_stalker

AddrFmt='L'

# Sample Notifier class
# Prints a statement for each type of event encountered
class CustomNotifier(vtrace.Notifier):
    # Event is one of the vtrace.NOTIFY_* things listed under vtrace

    def notify(self, event, trace):
        print "Got event: %d from pid %d" % (event, trace.getPid())
        print "PID %d thread(%d) got" % (trace.getPid(), trace.getMeta("ThreadId"))

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
            pass
        else:
            print "vtrace.NOTIFY_WTF_HUH?"

# Print out the value in EIP as a long
def getEIP(trace):
    eip = trace.getRegister(REG_EIP)
    return eip

# Print out the value in EIP as a hex number
def printableEIP(trace):
    return hex(getEIP(trace))

# Print out the value of ESP as a long
def getESP(trace):
    esp = trace.getRegister(REG_ESP)
    return esp

# Print out the value of the memory ESP points to
# if the program is stopped in the appropriate spot 
# this is the return value for the function.
def getRET(trace):
    esp = getESP(trace)
    retaddr = trace.readMemory(esp, 4)
    return struct.unpack("I",retaddr)[0]

# Same as above only in hex
def getPrintableRET(trace):
    esp = getESP(trace)
    retprt = trace.readMemory(esp, 4)
    return hex(struct.unpack("I",retaddr)[0])

def getOpCode(trace, eip):
    s = trace.readMemory(eip,15)
    op1 = trace.makeOpcode(s, 0, eip)
    return op1

def getSnapshot(trace):
    # Snapshot still broken when new features are enabled (Stalker)
    # might have something to do with the deep copy of the meta tags
    return vs_snap.takeSnapshot(trace)

def snapshotToFile(snap, filename):
    f = file(filename, "wb")
    f.write(str(snap))
    #pickle.dump(snap, f)
    f.close()

def getStalkerInfo(trace):
    print("STALKER BREAKS: ", trace.getMeta("StalkerBreaks"))
    print("STALKER HITS: ", trace.getMeta("StalkerHits"))
    print("STALKER CODE FLOW: ", trace.getMeta("StalkerCodeFlow"))

def getReconInfo(trace):
    print("RECON HITS: ", trace.getMeta("recon_hits"))
    print("RECON QUIET: ", trace.getMeta("recon_quiet"))
    print("TRACKER BREAK: ", trace.getMeta("TrackerBreak"))

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

# NOTE Not working yet
def setBpOnLib(trace, libname, regex):
    try:
       for sym in trace.searchSymbols(regex, libname=libname):

        symstr = str(sym)
        symval = long(sym)
        if trace.getBreakpointByAddr(symval) != None:
            print('Duplicate (0x%.8x) %s' % (symval, symstr))
            continue
        bp = vtrace.Breakpoint(None, expression=symstr)
        trace.addBreakpoint(bp)
        print('Added: %s' % symstr)

    except re.error, e:
        print('Invalid Regular Expression: %s' % regex)

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
