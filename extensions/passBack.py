'''
An extension module for vdb to pass control back to a script.

'''

def passback(db, line):
  '''
  Function to exit vdb without releasing the trace object
  
  Usage: passback

  Exits VDB without releasing the trace object
  '''
  
  db.shutdown.set()

def vdbExtension(db, trace):
  '''
  Regiser command withing vdb

  Usage: vdbExtension(db, trace)
  db    - An instance of VdbCli() (and therefor vdb...)
  trace - An example of a trace for the platform.
  '''

  # Here we use our reference to the vdb debugger object
  # to add a command extension.
  db.registerCmdExtension(passback)

