from scapy.all import *
import scapy.contrib.ospf


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
				# ospf_data.show()
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

			ospf_pkt.show()
		return ospf_pkt
	return pkt
	
def filter_ospf(packet):
    return OSPF_Hdr in packet


def process_packet(filename):
    """
    Function to process OSPF packets
    """
    def process_packet_temp(packet):
        packet = construct_ospf(packet)
        string = "---------------------------------------------------\n"
        ospf_header = packet[OSPF_Hdr]
        if ospf_header.type == 1 and OSPF_Hello in packet:
            ospf_hello = packet[OSPF_Hello]
            if ospf_header.authtype == 0:
                authtype = 'not authenticated'
            elif ospf_header.authtype == 1:
                password = bytes.fromhex(raw(ospf_header)[16:24].hex().rstrip("0")).decode()
                authtype = f'plain text authenticated (Password: {password})'
            elif ospf_header.authtype == 2:
                authtype = 'md5 authenticated'
            string += f"- OSPF version is {ospf_header.version}\n- OSPF is {authtype}\n- Area: {ospf_header.area}\n- OSPF Routers: {ospf_hello.neighbors}\n- DR Router: {ospf_hello.router}\n- BDR Router: {ospf_hello.backup}\n- Hello Interval: {ospf_hello.hellointerval}\n- Dead Interval: {ospf_hello.deadinterval}\n"
        elif packet[OSPF_Hdr].type == 4 and OSPF_LSUpd in packet:
            ospf_lsu = packet[OSPF_LSUpd]
            for lsa in ospf_lsu.lsalist:
                string += f"- Possible Link State ID: {lsa.id}\n- Possible Advertising Router: {lsa.adrouter}\n"

        string += "---------------------------------------------------"

        print(string)

        with open(filename, 'a') as f:
            f.write(string)
    return process_packet_temp


def sniff_ospf(iface, write_filepath):
    sniff(lfilter=filter_ospf, prn=process_packet(write_filepath), iface=iface)


if __name__ == "__main__":
    load_contrib("ospf")
    iface = "Wi-Fi"
    sniff_ospf(iface, 'sniff.log')
