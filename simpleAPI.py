#VDB_ROOT = "<path-to-VDB>"

import sys
sys.path.append(VDB_ROOT)

import vtrace
import vdb

import envi
import envi.archs.i386.disasm as dis
from envi.archs.i386 import *
import envi.memory as mem


import PE as PE
import vtrace.envitools as envitools
import vtrace.snapshot as vs_snap
import vdb.recon as v_recon
import vdb.recon.sniper as v_sniper
import vdb.stalker as v_stalker

AddrFmt='L'
debug = False

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
                if r.lower().find(pattern.lower()) == -1:
                     continue
            print("0x%.8x %s" % (sym.value, r))
            return sym.value

def setBpOnPattern(trace, pattern):
    addr = findFunc(trace, pattern)
    bp = vtrace.Breakpoint(addr)
    trace.addBreakpoint(bp)

def printBp(trace):
    for bp in trace.getBreakpoints():
        print("%s enabled: %s" % (bp, bp.isEnabled()))

def getOEP(trace, filepath):
    base = None

    libs = trace.getMeta("LibraryPaths")
    for k, v in libs.iteritems():
        if filepath in v:
            base = k
    
    if base is None:
        p = PE.peFromFileName(filepath)
        base = p.IMAGE_NT_HEADERS.OptionalHeader.ImageBase
    else:
        p = PE.peFromMemoryObject(trace, base)

    ep = p.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
    oep = base + ep
    return oep

# This function will change the input variables so that child process
# starts paused.  Then reads the PID of the newly created child process 
# and attaches to it
# NOTE: trace object should be at the _1st_ instruction in CreateProcessA
# for this to function.  Upon return you will be at OEP for child process 
def followCreateProcessA(trace):
    dwAddr = trace.getRegister(REG_ESP)

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
            trace.attach(pid)
            print "ADD TRACE: ", trace.getPid()
    except:
        pass

    return trace

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

# Will parse the PE in memory and return the array containing the IAT
# If verbose is true it will also print out the IAT
def printIAT(trace, filepath, verbose=False):
    base = None

    libs = trace.getMeta("LibraryPaths")
    for k, v in libs.iteritems():
        if filepath in v:
            base = k

    if base is None:
        p = PE.peFromFileName(filepath)
        base = p.IMAGE_NT_HEADERS.OptionalHeader.ImageBase
    else:
        p = PE.peFromMemoryObject(trace, base)

    IMAGE_DIRECTORY_ENTRY_IMPORT          =1   # Import Directory
    IMAGE_DIRECTORY_ENTRY_IAT            =12   # Import Address Table

    idir = p.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
    poff = p.rvaToOffset(idir.VirtualAddress)
    psize = idir.Size
    # Once you have VirtualAddress BP on that and you can stop 
    # the program before any external call.
   
    p.parseImports()
    if verbose == True:
        for i in p.imports:
            print("Address: %s \tLibrary: %s \tFirstThunk: %s" % (i[0], i[1], i[2]))
    return p.imports

# Will decode shellcode in a linear manner
# shellcode must be in the format '\x90\x90\xCC\xCC'
# for the code to function properly
def disasm(trace, shell):
    d = dis.i386Disasm()
    i = 0
    count = 0
    while count < len(shell):
        try:
            op = trace.makeOpcode(shell, offset=i, va=0)
            print "%14s:\t %s" %(shell[count:count+op.size].encode('hex'), op)
            #print "COUNT: ", count
            #print "OP SIZE: ", op.size
            i += 1
            count += op.size
        except:
            print "ERROR: ", sys.exc_info()[1]
            i += 1
            count += 1
            continue

############################################################
# Super ghetto, not recommended
def addOpCodeToList(opList):
    try:
        opList[getEIP(trace)] += 1
    except:
        opList[getEIP(trace)] = 1



def mainTemplate(argv):
    if len(argv) != 2:
        # sys.argv[0] is the name of the script
        print "Usage: %s <exe bin>" % sys.argv[0]
        sys.exit(1)

    # sys.argv[1] is the first argument passed to script
    filepath = sys.argv[1]
   
    load_binary(filepath)
    
# if __name__ == "__main__":
#     main(sys.argv)
#     sys.exit(0)