import os

def loadSymbols(trace, library, pdb=None):
  
  import PE as PE
  SYMBOLS_PATH = os.getenv('_NT_SYMBOL_PATH')
  if SYMBOLS_PATH == None:
    SYMBOLS_PATH = "C:\\Symbols"
  
  baseaddr = trace.getMeta('LibraryBases').get(library)

  if baseaddr == None:
    #raise Exception("%s library not loaded" % library)
    return 2
  else:
    pe = PE.peFromMemoryObject(trace, baseaddr)
    oh = pe.IMAGE_NT_HEADERS.OptionalHeader
    deb = pe.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[PE.IMAGE_DIRECTORY_ENTRY_DEBUG]
    virtaddr = deb.vsGetField('VirtualAddress')
    virtsize = deb.vsGetField('Size')
    poff = pe.rvaToOffset(virtaddr)

    if poff == 0:
      return 1

    imageDebugDirectory = pe.readStructAtOffset(poff, 'pe.IMAGE_DEBUG_DIRECTORY')
    addrRawData = imageDebugDirectory.vsGetField('AddressOfRawData')
    cvInfoPdb = pe.readStructAtOffset(addrRawData, 'pe.CV_INFO_PDB70')
    cvGuid = cvInfoPdb.vsGetField('GuidSignature')
    cvSig = cvInfoPdb.vsGetField('CvSignature')
    tmpGuid = cvGuid.vsGetFields()
    tmpGuid.sort()
    guid = bytearray(16)
    for elem in range(len(tmpGuid)):
      guid[elem] = tmpGuid[elem][1].vsGetValue()

    guid_str = str(guid).encode('hex')

    if pdb == None:
      sympath = os.getenv('_NT_SYMBOL_PATH')
      if sympath == None:
        # Guess that the symbols are in the typical spot for windows.
        sympath = SYMBOLS_PATH
        filename = sympath + "\\" + library + ".pdb\\" + guid_str + "1\\" + library + ".pdb"
    else:
      filename = pdb

    if os.path.isfile(filename):
      try:
        trace.parseWithDbgHelp(filename, baseaddr, library)
        return 0
      except:
        return 1
    else:
      return 1

