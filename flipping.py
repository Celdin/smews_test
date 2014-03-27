from random import *
from scapy.all import *
from sys import getsizeof

def flip(n,lower,upper):
	n ^= ((1<<upper)-1)&~((1<<lower)-1)
	return n

def packFlip(packet,verbose=False):

	choix = randrange(6)
	if choix == 0:
		if verbose :
			print "bitflipping sur total length"
		if IPv6 in packet:
			if verbose :
				print "valeur actuelle: " + str(getsizeof(packet[IPv6]))
			low = randrange(getsizeof(getsizeof(packet[IPv6])))
			packet[IPv6].len = getsizeof(packet[IPv6]) + flip(getsizeof(packet[IPv6]),low,low+1)
			if verbose :
				print "nouvelle valeur: " + str(packet[IPv6].len)
		else:
			if verbose :
				print "valeur actuelle: " + str(getsizeof(packet[IP]))
			low = randrange(getsizeof(getsizeof(packet[IP])))
			packet[IP].len = getsizeof(packet[IP]) + flip(getsizeof(packet[IP]),low,low+1)
			if verbose :
				print "nouvelle valeur: " + str(packet[IP].len)
	elif choix == 1:
		if verbose :
			print "bitflipping sur Header checksum"
			if IPv6 in packet:
				print "valeur actuel: " + str(packet[IPv6].chksum)
			else:
				print "valeur actuel: " + str(packet[IP].chksum)
		low = randrange(getsizeof(0))
		if IPv6 in packet:
			packet[IPv6].chksum = flip(0,low,low+1)
		else:
			packet[IP].chksum = flip(0,low,low+1)
		if verbose :
			if IPv6 in packet:
				print "nouvelle valeur: " + str(packet[IPv6].chksum)
			else:
				print "nouvelle valeur: " + str(packet[IP].chksum)
	elif choix == 2:
		if verbose :
			print "bitflipping sur Destination port"
		if verbose :
			print "valeur actuelle: " + str(packet[TCP].dport)
		low = randrange(getsizeof(packet[TCP].dport))
		packet[TCP].dport = flip(packet[TCP].dport,low,low+1)
		if verbose :
			print "nouvelle valeur: " + str(packet[TCP].dport)
	elif choix == 3:
		if verbose :
			print "bitflipping sur Ack num"
		if verbose :
			print "valeur actuelle: " + str(packet[TCP].ack)
		low = randrange(getsizeof(packet[TCP].ack))
		packet[TCP].ack = flip(packet[TCP].ack,low,low+1)
		if verbose :
			print "nouvelle valeur: " + str(packet[TCP].ack)
	elif choix == 4:
		if verbose :
			print "bitflipping sur Seq Num"
		if verbose :
			print "valeur actuelle: " + str(packet[TCP].seq)
		low = randrange(getsizeof(packet[TCP].seq))
		packet[TCP].seq = flip(packet[TCP].seq,low,low+1)
		if verbose :
			print "nouvelle valeur: " + str(packet[TCP].seq)
	elif choix == 5:
		if verbose :
			print "bitflipping sur Segment checksum"
		if verbose :
			print "valeur actuelle: " + str(packet[TCP].chksum)
		low = randrange(getsizeof(0))
		packet[TCP].chksum = flip(0,low,low+1)
		if verbose :
			print "nouvelle valeur: " + str(packet[TCP].chksum)
	return packet
