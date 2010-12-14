import sys
import vtrace
import vdb
import PE as PE
from envi.archs.i386 import *

# The following MUST be done otherwise windows catches the stopped program
# in a horrible attempt to "help". 
# Go to the following registry location and change the value data to 1.
# HKEY_CURRENT_USER\Software\ Microsoft\Windows\Windows Error Reporting\DontShowUI

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

    # Get a dictionary list of all DLL and PE files loaded by this PE 
    bases = trace.getMeta("LibraryBases")

    # The name variable needs to be changed depending on 
    # the name of the executable being run
    # Should be a regex
    name = "pwnables100"

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
                    # EVERLOVING HATRED OF REGEX
                    # Yes I know this isn't regex but it should be
                    # ... eventually
                    entryPoint = attr.split(': ')[1].split()[0]
                    print "Address Of Entry Point: ", entryPoint.strip(None)
                    
                if "ImageBase" in attr:
                    imageBase = attr.split(':')[1].split(' ')[1]
                    print "ImageBase: ", imageBase.strip(None)

            # Parse the PE sections for variables in the .text section
            for s in pobj.getSections():
                if s.Name.split("\x00", 1)[0] == '.text':
                    for sec in s.tree().split('\n'):
                        if "VirtualSize" in sec:
                            virtualSize = sec.split(': ')[1].split()[0]
                            print "VirtualSize: ", virtualSize
                        if "VirtualAddress" in sec:
                            virtualAddress = sec.split(': ')[1].split()[0]
                            print "VirtualAddress: ", virtualAddress
    
    # Original Entry Point is calculated as:
    # Entry Point + Image Base
    OEP = int(entryPoint, 0) + int(imageBase, 0)

    # Set breakpoint at address
    bp = vtrace.Breakpoint(OEP)
    trace.addBreakpoint(bp)

    # Print out all the current breakpoints as well as if they are enabled.
    for bp in trace.getBreakpoints():
        print("%s enabled: %s" % (bp, bp.isEnabled()))

    # Start executing the program until you hit a breakpoint or it ends
    trace.run()

    print "Holy BreakPoint Batman!"

