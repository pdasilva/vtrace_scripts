import vtrace
import vdb

if __name__ == "__main__":
    pid = None
    cmd = "C:\\Windows\\system32\\calc.exe"
    
    # Get the current vtrace object
    trace = vtrace.getTrace()

    # If attempting to attach to a 64 bit process
    # 64 bit python is required.
    if pid != None:
        trace.attach(pid)
    elif cmd != None:
        trace.execute(cmd)

    # Start the program executing
    trace.run()
