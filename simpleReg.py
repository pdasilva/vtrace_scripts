import sys
import vtrace
import vdb
import PE as PE
from envi.archs.i386 import *

# Function that finds the Original Entry Point
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
######################################################################
    # Call a function to set BP on OEP
    oep = getOEP(trace, "pwnables100")

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
