# Sample scripts to run in vdb

## simpleIAT_NX_vdb
> Extension of simpleIAT script.  Scripts will set the IAT of a binary to unreadable causing a signal to be thrown on each external library reference and call.  The signal is then caught by a custom notifier class that will log them into a list in the order they were called, and continue the program.  Once process ends it will print out the list of called functions.
> simpleIAT_NX_vdb is meant to be started within an already running vdb instance
