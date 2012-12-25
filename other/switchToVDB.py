def switchToVDB(trace):
  import vdb
  db = vdb.Vdb(trace)
  while not db.shutdown.isSet():
    try:
      db.cmdloop()

    except KeyboardInterrupt:
      if db.trace.isRunning():
        db.trace.sendBreak()
    except SystemExit:
      break
    except:
      traceback.print_exc()
