import idaapi
import idc

# color = 0xBBGGRR
# use DEFCOLOR to remove coloring

# use offsets from base address to fix how ida sees things
fn = idc.AskFile(0, "*.stalk", "Select stalker output file to view")
if not fn:
	pass
else:
	file = open(fn, 'r')
	a = file.read().split('\n\t ')

	for i in range(len(a)):
		a[i] = a[i].strip()

	for i in a:
		if isEnabled(int(i,16)):
			print "ADDR: %s" % i
			idc.SetColor(int(i,16), CIC_ITEM, 0x00AAFF)
idaapi.refresh_idaview_anyway()

#idc.Exit(0)
