import sys
import simpleAPI as v_api
#VDB_ROOT = "<path-to-VDB>"

sys.path.append(VDB_ROOT)

import vtrace
import vdb

import envi
import envi.memory as mem
from envi.archs.i386 import *

import vtrace.envitools as envitools

import PE
import vstruct

import vdb.recon as v_recon
import vdb.recon.sniper as v_sniper
import vdb.stalker as v_stalker

debug = True

#######################################################################
def load_binary(filepath, base=None):
    
    trace = vtrace.getTrace()
    trace.execute(filepath)
    #######################################################################
    # Call a function to set BP on OEP
    oep = v_api.getOEP(trace, filepath)

    # Set breakpoint at address
    bp = vtrace.Breakpoint(oep)
    trace.addBreakpoint(bp)

    ######################################################################
    # Start executing the program until you hit a breakpoint or it ends
    trace.run()
    #######################################################################
    # function takes in just filename not the full path to filename.exe
    exeName = filepath.split(".exe")[0]
    fileName = exeName.split("\\")[len(exeName.split("\\"))-1]

    # Get the list of imported functions to compare against
    base, importTable = v_api.printIAT(trace, fileName, debug)

#######################################################################
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
