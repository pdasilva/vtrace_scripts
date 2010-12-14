import sys
import vtrace
import vdb
from envi.archs.i386 import *


if __name__ == "__main__":
    pid = 3348
    cmd = None
    
    # Ask for the current trace object so we can play with it
    trace = vtrace.getTrace()

    # If attempting to attach to a 64 bit process
    # 64 bit python is required.
    if pid != None:
        trace.attach(pid)
    elif cmd != None:
        trace.execute(cmd)

    # Start executing the program.  
    # Will not stop until it finishes or is killed    
    trace.run()
