from scapy.all import *
from flipping import *
import sys, os

verbose = False

for arg in sys.argv[1:]:
	if verbose :
		print arg
	if arg.startswith("file="):
		t, e, filename = arg.partition("=")
	if arg.startswith("-v"):
		verbose = True;

pack = rdpcap(filename)
i = 0
while i<len(pack):
	if IPv6 in pack[i]:
		pack[i] = pack[i][IPv6]
		del(pack[i][IPv6].chksum)
	else:
		pack[i] = pack[i][IP]
		del(pack[i][IP].chksum)
	del(pack[i][TCP].chksum)
	pack[i] = packFlip(pack[i],verbose)
	if pack[i][TCP].flags == 'A':
		sr(pack[i],timeout=0)
	else:
		sr1(pack[i],timeout=0.0001)
	if verbose :
		print `i+1`+" sur "+`len(pack)`+" requette envoye."
	i = i + 1
