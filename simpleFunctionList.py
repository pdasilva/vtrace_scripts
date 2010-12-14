import sys
import vtrace
import vdb
import PE as PE
from envi.archs.i386 import *
import vdb.stalker as v_stalker

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

    # Pattern is the dll you want to search for function names in
    pattern = 'ntdll'
    pattern = pattern.lower()

    # Get the list of all library names
    # Iterate over the list of function names for values that match pattern
    libs = trace.getNormalizedLibNames()
    libs.sort()
    for libname in libs:
        for sym in trace.getSymsForFile(libname):
            r = repr(sym)
            if pattern != None:
                if r.lower().find(pattern) == -1:
                     continue
            print("0x%.8x %s" % (sym.value, r))
