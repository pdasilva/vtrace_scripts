import sys
import os

import time
import threading

# Change this to your vdb path
VDB_ROOT = ""
sys.path.append(VDB_ROOT)

import vtrace
import vdb
from envi.archs.i386 import *

# Hard coded for IE
exepath = "C:\Program Files (x86)\Internet Explorer\iexplore.exe"

#######################################################################
def getOpCode(trace, eip):
    s = trace.readMemory(eip,15)
    op1 = trace.makeOpcode(s, 0, eip)
    return op1

def printInfo(trace):
    # print ("DIR: %s") % (dir(trace))

    # print("META: %s") % (trace.metadata)
    eip = trace.getRegisterByName("eip")


    dis = getOpCode(trace, trace.getRegister(REG_EIP))
    disLen = len(dis)
    opcode = trace.readMemory(eip, len(dis))

    es = trace.getRegisterByName("es")
    ds = trace.getRegisterByName("ds")
    cs = trace.getRegisterByName("cs")
    
    ef = trace.getRegisterByName("eflags")

    edi = trace.getRegister(REG_EDI)
    esi = trace.getRegister(REG_ESI)
    esp = trace.getRegister(REG_ESP)

    print "[*] Bestname: ", trace.getSymByAddr(eip, exact=False)
    print "%16s: %s" % ("EIP", hex(eip))
    
    print "%16s: %s" % ("DIS", dis)
    print "%16s: %s" % ("OPCODE", repr(opcode))
    print "%16s: %s" % ("ES", es)
    print "%16s: %s" % ("DS", ds)
    print "%16s: %s" % ("CS", cs)
    print "%16s: %s" % ("EAX", hex(trace.getRegister(REG_EAX)))
    print "%16s: %s" % ("EBX", hex(trace.getRegister(REG_EBX)))
    print "%16s: %s" % ("ECX", hex(trace.getRegister(REG_ECX)))
    print "%16s: %s" % ("EDX", hex(trace.getRegister(REG_EDX)))
    
    print "%16s: %s" % ("EDI", hex(edi))
    print "%16s: %s" % ("ESI", hex(esi))

    print "%16s: %s" % ("ESP", hex(esp))
    print "%16s: %s" % ("[ESP]", repr(trace.readMemory(esp, 4)))
    
    print("%16s: %s" % ("Direction", bool(ef & EFLAGS_DF)))


#######################################################################
def load_binary(trace, filepath, base=None):
    global exepath

    # If attempting to attach to a 64 bit process
    # 64 bit python is required.
    # sample cmdline: C:\Program Files (x86)\Internet Explorer\iexplore.exe C:\test\ie\index_0.html
    cmdline = exepath + " " + filepath
    trace.execute(cmdline)

    print("Executing: %s") % (cmdline)
    # Start the program executing
    trace.run()

######################################################################
def main(argv):
    global exepath

    if len(argv) != 2:
        print "Usage: %s <test files>" % sys.argv[0]
        sys.exit(1)

    # verify that the path to test files is valid
    filepath = sys.argv[1]
    if os.path.isdir(filepath) == False:
        sys.exit("Invalid Input Directory")

    # Get the current vtrace object
    trace = vtrace.getTrace()

    threads = []
    crashes = []
    count = 1
    print ("[*] Starting fuzz process")

    # call load_binary on the filenames stored in the directory
    for fname in os.listdir(filepath):
        #print fname
        cmdline = filepath + "\\" + fname
        
        t = threading.Thread(target = load_binary, args = (trace, cmdline,))
        threads.append(t)
        t.start()
        time.sleep(10)
        if trace.isRunning():
            trace.sendBreak()
            printInfo(trace)

            print ("[*] Death to the process %d") % (trace.getPid())
            trace.kill()
        else:
            print ("[*] %s crashed") % (fname)
        time.sleep(1)
        count += 1

    print ("")
    print ("[*] Death to all %d of %d processes") % ( (count-len(crashes)), count )
    print ("[*] %d files caused crashes") % (len(crashes))
    for i in crashes:
        print ("\t filename: %s") % (i)

if __name__ == "__main__":
    main(sys.argv)
    sys.exit(0)
