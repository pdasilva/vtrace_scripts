import sys
import vtrace
import vdb
import PE as PE
from envi.archs.i386 import *
import vdb.stalker as v_stalker
import vtrace.snapshot as vs_snap

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

def getSnapshot(trace):
    # Snapshot still broken when new features are enabled (stalker)
    # might have something to do with the deep copy of the meta tags
    return vs_snap.takeSnapshot(trace)

def snapshotToFile(snap, filename):
    f = file(filename, "wb")
    f.write(str(snap))
    #pickle.dump(snap, f)
    f.close()



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
    
    # Call a function to set BP on OEP
    oep = getOEP(trace, "pwnables100")

    # Set breakpoint at address
    bp = vtrace.Breakpoint(oep)
    trace.addBreakpoint(bp)

    # Start executing the program until you hit a breakpoint or it ends
    trace.run()
#################################################################

    # takes a snapshot of memory
    snap = vs_snap.takeSnapshot(trace)
    # saves it to a file
    snap.saveToFile("zTest.snap")

    # loads a snapshot from a filename
    #snap.loadSnapshot("zTest.snap")
    
