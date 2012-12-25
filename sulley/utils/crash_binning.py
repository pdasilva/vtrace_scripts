#
# Crash Binning
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: crash_binning.py 193 2007-04-05 13:30:01Z cameron $
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

'''
@author:       Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
'''

import cPickle
import pprint
import sys
import zlib

import distorm3

class __crash_bin_struct__:
  exception_module    = None
  exception_address   = 0
  write_violation     = 0
  violation_address   = 0
  violation_thread_id = 0
  context             = None
  context_dump        = None
  disasm              = None
  disasm_around       = []
  stack_unwind        = []
  seh_unwind          = []
  extra               = None

def __getitem__(self, key): 
  return self.data[key]


class crash_binning:
  '''
  @todo: Add MySQL import/export.
  '''

  bins       = {}
  last_crash = None
  trace      = None
  arch       = '32' # by default we use x86 architecture
  
  ####################################################################################################################
  def __init__ (self):
    '''
    '''

    self.bins       = {}
    self.last_crash = None
    self.trace      = None


  ####################################################################################################################
  def set_architecture(self, arch):
    '''
    set the architecture to use during disassembly. default is 32bit.
    
    @type  arch: string
    @param arch: string value representing bit architecture for disassembly
    '''
    if arch == '16':
      self.arch = '16'
    elif arch == '32':
      self.arch = '32'
    elif arch == '64':
      self.arch = '64'
    else:
      print '[!] danger: architecture probably not supported!'
      self.arch = arch


  ####################################################################################################################
  def record_crash (self, trace, extra=None):
    '''
    Given a vtrace instantiation that at the current time is assumed to have "crashed" (access violation for example)
    record various details such as the disassemly around the violating address, the ID of the offending thread, the
    call stack and the SEH unwind. Store the recorded data in an internal dictionary, binning them by the exception
    address.

    @type  trace: vtrace
    @param trace: Instance of vtrace
    @type  extra: Mixed
    @param extra: (Optional, Def=None) Whatever extra data you want to store with this bin
    '''

    self.trace = trace
    crash = __crash_bin_struct__()

    # add module name to the exception address.
    exception_module = trace.getSymByAddr(trace.getMeta('Win32Event')['ExceptionAddress'], False)

    if exception_module:
      pass
    else:
      exception_module = "[INVALID]"

    crash.exception_module    = exception_module
    crash.exception_address   = trace.getMeta('Win32Event')['ExceptionAddress']
    crash.write_violation     = trace.getMeta('Win32Event')['ExceptionInformation'][0]
    crash.violation_address   = trace.getMeta('Win32Event')['ExceptionInformation'][1]
    crash.violation_thread_id = trace.getMeta('ThreadId')
    crash.context             = self.register_context(trace, thread=crash.violation_thread_id)
    crash.context_dump        = self.dump_register_context(crash.context, print_dots=False)
    crash.disasm              = trace.parseOpcode(crash.exception_address)
    crash.disasm_around       = self.disasm_around(trace, crash.exception_address, 10)
    crash.stack_unwind        = trace.getStackTrace()
    crash.seh_unwind          = self.seh_unwind(trace)
    crash.extra               = extra

    # add module names to the stack unwind.
    for i in xrange(len(crash.stack_unwind)):
      addr   = crash.stack_unwind[i][0]
      frame  = crash.stack_unwind[i][1]
      try:
        rva = self.addr_to_rva(trace, program_counter)
      except:
        rva = ''
      crash.stack_unwind[i] = "rva: %s\t addr: 0x%08x\t frame:0x%08x" \
                              % (rva, addr, frame)

    # add module names to the SEH unwind.
    for i in xrange(len(crash.seh_unwind)):
      (addr, handler) = crash.seh_unwind[i]
      try:
        rva = self.addr_to_rva(trace, handler)
      except:
        rva = ''
      crash.seh_unwind[i] = (addr, handler, "%s" % (rva, ))

    if not self.bins.has_key(crash.exception_address):
      self.bins[crash.exception_address] = []

    self.bins[crash.exception_address].append(crash)
    self.last_crash = crash


  ####################################################################################################################
  def disasm_around(self, trace, starting_addr, size):
    '''
    returns the disassembly starting at addr for size instructions.
    
    @type  trace: vtrace
    @param trace: instance of vtrace
    @type  addr: int
    @param addr: address where to begin disassembly
    @type  size: int
    @param size: number of instructions to disassemble
    '''
    disasm = []
    try:
      code = trace.readMemory(starting_addr, size)
    except:
      raise Exception("unable to read memory for disasm")
    
    if self.arch == '32':
      asm_arch = distorm3.Decode32Bits
    elif self.arch == '64':
      asm_arch = distorm3.Decode64Bits
    elif self.arch == '16':
      asm_arch = distorm3.Decode16Bits
      
    for inst in distorm3.DecomposeGenerator(starting_addr, 
                                            code, 
                                            asm_arch): 
      if not inst.valid:
        return disasm
      else:
        disasm.append(inst)
    return disasm

  ####################################################################################################################
  def dump_register_context(self, regs, print_dots=False):
    """
    grab the values for each register

    @type  trace: vtrace
    @param trace: Instance of vtrace
    @type  print_dots: boolean
    @param print_dots: print dots for non-ascii characters

    @rtype:  string
    @return: ascii string representation of register contexts
    """
    register_string = ""
   
    for i in sorted(regs.keys()):
      ascii_view = ""
      bytes_view = []
      for byte in str(regs[i]):
        if ord(byte) >= 0x20 and ord(byte) < 0x7f:
          ascii_view += byte
        else:
          if print_dots:
            ascii_view += '.'
        bytes_view.append("\\x%02x" % ord(byte))
      register_string += '%s: %s-> %s\n' % (i, ''.join(bytes_view), ascii_view, )
    return register_string

  ####################################################################################################################
  def register_context(self, trace, thread=None):
    """
    grab the values for each register

    @type  trace: vtrace
    @param trace: Instance of vtrace

    @rtype:  dict
    @return: register contexts
    """
    registers = {}
    count = 0
    
    if not(thread):
      regs = trace
    else:
      regs = trace.getRegisterContext(threadid=thread)
      
    for reg in regs.getRegisterNames():
      registers[reg] = regs.getRegisterByName(reg)
    return registers
 

  ####################################################################################################################
  def stack_unwind(self, trace, thread=None):
    '''
    walk and save the stack trace for the current (or specified) thread.
    will be saved in the format [rva, instr addr, frame pointer]

    @type  trace: vtrace
    @param trace: Instance of vtrace
    @type  thread: integer
    @param thread: id of thread to process seh chain

    @rtype:  list
    @return: list containing stack trace in (rva, instr addr, frame pointer) format
    '''
    call_chain = trace.getStackTrace()
    
    for i in xrange(len(call_chain)):
      addr  = call_chain[i][0]
      frame = call_chain[i][1]
      try:
        rva = self.addr_to_rva(trace, addr)
      except:
        rva = ''
      call_chain[i] = "rva: %20s\t addr: 0x%08x\t frame:0x%08x" \
                      % (rva, addr, frame)

    return call_chain


  ####################################################################################################################
  def seh_unwind(self, trace, thread=None):
    '''
    walk and save the SEH chain for the current (or specified) thread.
    will be saved in the format [reg record addr, handler]
    adapted from vdb/vdb/extensions/windows.py seh(vdb, line)

    @type  trace: vtrace
    @param trace: Instance of vtrace
    @type  thread: integer
    @param thread: id of thread to process seh chain

    @rtype:  list
    @return: list containing seh chain in (reg record addr, handler) format
    '''
    seh_chain = []

    if not(thread):
      thread = trace.getMeta('ThreadId')

    thread_info = trace.getThreads().get(thread, None)
    if not(thread_info):
      raise Exception("Unknown Thread Id: %d" % thread)

    teb = trace.getStruct("ntdll.TEB", thread_info)
    addr = long(teb.NtTib.ExceptionList)
    while addr != 0xffffffff:
      er = trace.getStruct("ntdll.EXCEPTION_REGISTRATION_RECORD", addr)
      seh_chain.append((addr, er))
      addr = long(er.Next)
    return seh_chain


  ####################################################################################################################
  def addr_to_rva(self, trace, addr):
    """
    Convert a virtual address to the RVA with a module name so we 
    can find it even with ASLR.

    @type  trace: vtrace
    @param trace: Instance of vtrace
    @type  addr: integer
    @param addr: address to convert to relative virtual address (rva)

    @rtype:  string
    @return: string representation of rva in [module base]+offset format
    """
    sym_for_addr = ''
    if trace.getSymByAddr(addr , False):
      sym_for_ret_addr = '[ ' + trace.getSymByAddr(addr, False) + ']'

    mem_map = trace.getMemoryMap(addr)

    if not(mem_map):
      raise Exception("memory not mapped")

    rva = addr - mem_map[0]
    base_module = mem_map[3][mem_map[3].rfind('\\'):].replace('\\','')
    base_module = base_module.replace('.dll','')

    return base_module + ('+%08x' % rva) + ' ' + sym_for_addr


  ####################################################################################################################
  def crash_synopsis (self, crash=None):
    '''
    For the supplied crash, generate and return a report containing the disassemly around the violating address,
    the ID of the offending thread, the call stack and the SEH unwind. If no crash is specified, then return the 
    same information for the last recorded crash.

    @see: crash_synopsis()

    @type  crash: __crash_bin_struct__
    @param crash: (Optional, def=None) Crash object to generate report on

    @rtype:  String
    @return: Crash report
    '''

    if not crash:
      crash = self.last_crash

    if crash.write_violation:
      direction = "write to"
    else:
      direction = "read from"

    synopsis = "%s:%08x %s from thread %d caused access violation\nwhen attempting to %s 0x%08x\n\n" % \
      (
        crash.exception_module,       \
        crash.exception_address,      \
        crash.disasm,                 \
        crash.violation_thread_id,    \
        direction,                    \
        crash.violation_address       \
      )

    synopsis += crash.context_dump

    synopsis += "\ndisasm around:\n"
    for inst in crash.disasm_around:
      synopsis += "\t0x%08s %s\n" % (hex(inst.address).replace('L',''),
                                     str(inst))

    if len(crash.stack_unwind):
      synopsis += "\nstack unwind:\n"
      for entry in crash.stack_unwind:
        synopsis += "\t%s\n" % entry

    if len(crash.seh_unwind):
      synopsis += "\nSEH unwind:\n"
      for (addr, handler, handler_str) in crash.seh_unwind:
        try:
          disasm = trace.parseOpcode(addr)
        except:
          disasm = "[INVALID]"

        synopsis +=  "\t0x%08x -> %s\t %s\n" % (addr, handler_str, disasm)

    return synopsis + "\n"


  ####################################################################################################################
  def export_file (self, file_name):
    '''
    Dump the entire object structure to disk.

    @see: import_file()

    @type  file_name:   String
    @param file_name:   File name to export to

    @rtype:             crash_binning
    @return:            self
    '''

    # null out what we don't serialize but save copies to restore after dumping to disk.
    last_crash = self.last_crash
    trace      = self.trace

    self.last_crash = self.trace = None

    fh = open(file_name, "wb+")
    fh.write(zlib.compress(cPickle.dumps(self, protocol=2)))
    fh.close()

    self.last_crash = last_crash
    self.trace      = trace

    return self


  ####################################################################################################################
  def import_file (self, file_name):
    '''
    Load the entire object structure from disk.

    @see: export_file()

    @type  file_name:   String
    @param file_name:   File name to import from

    @rtype:             crash_binning
    @return:            self
    '''

    fh  = open(file_name, "rb")
    tmp = cPickle.loads(zlib.decompress(fh.read()))
    fh.close()

    self.bins = tmp.bins

    return self


  ####################################################################################################################
