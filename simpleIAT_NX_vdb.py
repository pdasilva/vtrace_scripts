import os
import sys


#VDB_ROOT = "<path-to-VDB>"
#API_ROOT = "<path-to-simpleAPI.py>"

sys.path.append(VDB_ROOT)
sys.path.append(API_ROOT)

#import simpleAPI as v_api
from simpleAPI import getOpCode, getIATLocation, printIAT, store_IAT, nxMemPerm, getOEP, printInfo


import vtrace
# import vdb

import envi
import envi.memory as mem
from envi.archs.i386 import *

import vtrace.envitools as envitools

import PE
import vstruct

# import vdb.recon as v_recon
# import vdb.recon.sniper as v_sniper
# import vdb.stalker as v_stalker

debug = True

###################################################################
class CustomNotifier(vtrace.Notifier):
    def notify(self, event, trace):
        iat_handler(event, trace)

#######################################################################
# Call this function from within a notifier to handle breakpoints on IAT
def iat_handler(event, trace):
    print "[*] Got event: %d from pid %d" % (event, trace.getPid())

    if event == vtrace.NOTIFY_ALL:
            print "WTF, how did we get a vtrace.NOTIFY_ALL event?!?!"

    elif event == vtrace.NOTIFY_SIGNAL:
        #print "vtrace.NOTIFY_SIGNAL"
        print "[*] PendingSignal",trace.getMeta("PendingSignal")
        print "[*] PendingException",trace.getMeta("PendingException")
        if trace.getMeta("Platform") == "Windows":
            begin = trace.getMeta("IATBegin")
            size = trace.getMeta("IATSize")
            print "[*] Removing Memory Protections Location: %s" % hex(begin)
            print "[*] Memory Size: %s" % size
            trace.protectMemory(begin, size, envi.memory.MM_RWX)
            
            # because MSVC debugger sucks at life 
            # 1080890248 (0x406d1388) is an exception used to name a thread
            # 3765269347 (0xe06d7363) is an exception that is triggered when a throw happens
            if (trace.getMeta("PendingSignal") != None) and \
                (trace.getMeta("PendingSignal") != 1080890248) and\
                (trace.getMeta("PendingSignal") != 3765269347):

                win32event = trace.getMeta("Win32Event")
                print "[*] ExceptionAddress: %(ExceptionAddress)x" % win32event
                
                eip = trace.getRegister(REG_EIP)
    
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
                
                printInfo(trace)
                
                if (len(opcode) == 1):
                    pass

                # What is this for again?
                # scasd i think \x66\xF2
                elif (ord(opcode[0]) != 102 and ord(opcode[1]) != 242):

                    # function takes in just filename not the full path to filename.exe
                    filepath = trace.getMeta('ExeName')
                    exeName = filepath.split(".exe")[0]
                    fileName = exeName.split("\\")[len(exeName.split("\\"))-1]

                    if(trace.getMeta('IATLocation') == None):
                        base, poff, psize = getIATLocation(trace, fileName)
                        trace.setMeta('IATLocation', {'base':base, 'poff':poff, 'psize':psize})
                    else:
                        iatLoc = trace.getMeta('IATLocation')
                        base = iatLoc['base']
                        poff = iatLoc['poff']
                        psize = iatLoc['psize']

                    eip = trace.getRegister(REG_EIP)
                    dis = getOpCode(trace, trace.getRegister(REG_EIP))
                    
                # Check for \xff to determine if a deref call
                if (ord(opcode[0]) == 255):
                    print "OPCODE[1]: ", ord(opcode[1])

                    # Need to accomodate more than just call [eax] and call [edx]
                    if (ord(opcode[1]) == 48):
                        eax = trace.getRegister(REG_EAX)
                        tmp_addr = struct.unpack("I",trace.readMemory(eax, 4))[0]
                    elif (ord(opcode[1]) == 16):
                        eax = trace.getRegister(REG_EAX)
                        tmp_addr = struct.unpack("I",trace.readMemory(eax, 4))[0]
                    elif (ord(opcode[1]) == 18):
                        edx = trace.getRegister(REG_EDX)
                        tmp_addr = struct.unpack("I",trace.readMemory(edx, 4))[0]


                    elif (ord(opcode[1]) == 80):
                        print "OPCODE[2]: ", ord(opcode[2])
                        #if (ord(opcode[2]) == 24):
                        eax = trace.getRegister(REG_EAX)
                        #eax += 24
                        eax += ord(opcode[2])
                        tmp_addr = struct.unpack("I",trace.readMemory(eax, 4))[0]
                        #print "EAX+24: %s" % repr(tmp_addr)

                    elif (ord(opcode[1]) == 112):
                        print "OPCODE[2]: ", ord(opcode[2])
                        eax = trace.getRegister(REG_EAX)
                        eax += ord(opcode[2])
                        tmp_addr = struct.unpack("I",trace.readMemory(eax, 4))[0]
                    elif (ord(opcode[1]) == 215):
                        edi = trace.getRegister(REG_EDI)
                        tmp_addr = struct.unpack("I",trace.readMemory(edi, 4))[0]
                    
                    else :
                        tmp_addr = struct.unpack("I",opcode[len(dis)-4:len(dis)])[0]

                        ################################
                        # Get the list of imported functions to compare against
                        try:
                            instr = trace.getMeta('IATInfo')    
                        except:
                            base, importTable = printIAT(trace, fileName)
                            store_IAT(trace, base, importTable, "IATInfo")
                            instr = trace.getMeta('IATInfo')
                        
                        print "TMP_ADDR: %s" % hex(tmp_addr)
                        try:
                            a = instr[tmp_addr]
                        except:
                            a = "UNKNOWN LIB: UNKNOWN FUNCTION"

                        b = a.split(':')

                        print "[*] \tLibrary: %s \n[*] \tFunction: %s" % (b[0], b[1])
                        
                        try:
                            lst = trace.getMeta('IATList')
                            lst.append(hex(tmp_addr)+':'+b[0]+':'+b[1])
                            trace.setMeta('IATList', lst)
                        except:
                            print "SET Initial IATList Metadata"
                            trace.setMeta('IATList', [hex(tmp_addr)+':'+b[0]+':'+b[1]])

                print "%16s: %s" % ("[*] Opcode[0]", ord(opcode[0]))

                p = trace.getMeta('PendingSignal')
                if p!= None:
                    trace.setMeta('OrigSignal', p)
                    trace.setMeta('PendingSignal', None)
                    
            print "STEPS"
            trace.stepi()
            
            print "[*] Protecting Memory Location: %s" % hex(begin)
            print "[*] Memory Size: %s" % size
            trace.protectMemory(begin, size, envi.memory.MM_NONE)

            print "Run Again Set"
            trace.runAgain(val=True)
                
            print "---------------------------------------------------------"
    elif event == vtrace.NOTIFY_BREAK:
        print "vtrace.NOTIFY_BREAK", hex(trace.getRegister(REG_EIP))
        print "[*] Bestname: ", trace.getSymByAddr(trace.getRegister(REG_EIP), exact=False)
        pass
    elif event == vtrace.NOTIFY_SYSCALL:
        print "vtrace.NOTIFY_SYSCALL"

    elif event == vtrace.NOTIFY_CONTINUE:
        print "vtrace.NOTIFY_CONTINUE"
        trace.runAgain(val=True)
        print "---------------------------------------------------------"

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

    else:
        print "vtrace.NOTIFY_WTF_HUH?", hex(trace.getRegister(REG_EIP))

#######################################################################
def load_binary(filepath, base=None):
    
    trace.setMode("FastStep", 1)

    filepath = trace.getMeta('ExeName')
    fileName = os.path.basename(filepath).split('.')[0]

    # Call a function to set BP on OEP
    oep = getOEP(trace, filepath)

    #######################################################################
    # Get the list of imported functions to compare against
    base, importTable = printIAT(trace, fileName)
    
    base, poff, psize = getIATLocation(trace, fileName, debug)

    # Store the IAT under the meta name IATInfo
    store_IAT(trace, base, importTable, "IATInfo")
    
    psize = trace.arch.getPointerSize()

    memMap = trace.getMemoryMap(base+poff)
    begin = memMap[0]
    size = len(importTable) * psize

    # put begin in size into the meta data
    trace.setMeta("IATBegin", begin)
    trace.setMeta("IATSize", size)

    print "[*] Protecting Memory Location: %s" % hex(begin)
    print "[*] Memory Size: %s" % size

    trace.protectMemory(begin, size, envi.memory.MM_NONE)

    #######################################################################
    # Enable the notifier.  Used later to catch the page execute exception.
    notif = CustomNotifier()
    eve = vtrace.NOTIFY_ALL
    #eve = vtrace.NOTIFY_SIGNAL
    trace.registerNotifier(eve, notif)


#######################################################################
######################################################################
load_binary("FOO")