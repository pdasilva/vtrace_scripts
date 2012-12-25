'''
An extension module for vdb that will load symbols for a given library

'''
import os


def loadsyms(db, line):
  '''
  A doc string for the function, becomes the doc string for the command line interface
  
  Usage: loadsyms <library> <pdb>
  
  args: space delimited
    library: string containing the name of the library to load symbols for
    (optional) pdb: path to the pdb file for that library

  Loads the symbols for a given library
  '''
  import imp
  import os
  
  try:
    library, pdb = line.split()
  except:
    library = line
    pdb = None
    
  trace = db.getTrace()
  
  VDB_EXTENSION = os.getenv('VDB_EXT_PATH')
  if VDB_EXTENSION == None:
    VDB_EXTENSION = os.path.dirname(os.getcwd())
  path = VDB_EXTENSION + '\\scripts\\loadSymbols.py'
  loadSym = imp.load_source('loadSym', path)
  symbols = loadSym.loadSymbols(trace, library, pdb=pdb)
  
  if symbols == 0:
    db.vprint ("[*] symbols for %s: loaded successfully" % library)
  elif symbols == 1:
    db.vprint ("[*] symbols for %s: failed to load" % library)
  elif symbols == 2:
    db.vprint ("[*] %s library not loaded" % library)
  

def vdbExtension(db, trace):
  '''
  Regiser command withing vdb

  Usage: vdbExtension(db, trace)
  db    - An instance of VdbCli() (and therefor vdb...)
  trace - An example of a trace for the platform.
  '''

  # Here we use our reference to the vdb debugger object
  # to add a command extension.
  db.registerCmdExtension(loadsyms)

