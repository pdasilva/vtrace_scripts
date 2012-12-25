# Sample scripts and things related to vtrace/vdb

## command_line
> Scripts that can be run from the command prompt.  
> This is where all the old scripts went...

## extensions
> Uses the new(ish) vtrace extension capability to add new commands into vdb.
> 
> **NOTE:** Must set VDB_EXT_PATH as an environment variable.

### extensions/scripts
> The logic needed for the extensions is kept in this folder.  Some extensions
> will typically add this directory to its path.

## ida
> Folder for scripts that parse vdb data into ida

## other
> vtrace code snippets... 

## presentations
> A few presentations about the vdb/vtrace api. Hopefully useful to some...

## sulley
> Drop in replacement files for sulley that use vtrace instead of pydbg.
> Just replace process_monitor.py and utils/crash_binning.py and it will use vtrace.
> Currently only tested on windows...

## vdb
> scripts that can be run within the vdb debugger using the script command.

