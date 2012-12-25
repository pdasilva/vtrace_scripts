# extensions
> Uses the new(ish) vtrace extension capability to add new commands into vdb.
> 
> **NOTE:** Must set VDB_EXT_PATH as an environment variable.

## loadSyms.py
> will attempt to load a pdb file from a path.
>
> usage: loadsyms <library> <pdb>

## passBack.py
> Allows the debugger to hand execution control back to a running command line script.

# extensions/scripts
> The logic needed for the extensions is kept in this folder.  Some extensions
> will typically add this directory to its path.

## loadSymbols.py
> The logic to load symbols is stored in this script.
