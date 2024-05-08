import os
from scapy.all import *
from hashlib import md5


BRUTE_FORCE_MIN_LENGTH = 1
BRUTE_FORCE_MAX_LENGTH = 8


class MD5_Cracker:
    def __init__(self, method, pkts):
        self.crack_method = method
        self.pkts = pkts
        self.cracked = list()
        if self.crack_method == 'bruteforce':
            self.characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}:;"\'<>,./?\\|`~'
    
    def md5_checker(self, key, cracked=False):
        """OSPF MD5 hash cracker
        Args:
            pkts (list): list of OSPF packets
            key (str): encoded authentication key
        """
        for pkt in self.pkts:
            # Calculates the packet data to hash
            if pkt not in self.cracked:
                auth_data = pkt[0] + key.hex().ljust(32, '0') if len(key.hex()) < 32 else pkt[0] + key.hex()[:32]
                if md5(bytes.fromhex(auth_data)).hexdigest() == pkt[1]:
                    print('[+] Cracked: ', pkt[1], key.decode())
                    self.cracked.append(pkt)
                    cracked = True
                    if len(self.pkts) == len(self.cracked):
                        return
        if not cracked:
            print("[-] Failed : ", key.decode())
    
    def crack(self, wordlist=None, min_len=BRUTE_FORCE_MIN_LENGTH, max_len=BRUTE_FORCE_MAX_LENGTH):
        if not self.pkts:
            print("No valid OSPF packet to crack!")
            return
        if self.crack_method == 'bruteforce':
            for length in range(min_len, max_len):
                for combination in itertools.product(self.characters, repeat=length):
                    key = ''.join(combination).encode()
                    self.md5_checker(key)
                    if len(self.pkts) == len(self.cracked):
                        print("All OSPF packets cracked")
                        return
        elif self.crack_method == 'rockyou':
            if not wordlist:
                print("Supply a wordlist to crack with.")
                return
            with open(wordlist, 'r') as file:
                for key in file:
                    key = bytes(key.strip("\n").strip("\r").encode())
                    self.md5_checker(key)
                    if len(self.pkts) == len(self.cracked):
                        print("All OSPF packets cracked")
                        return
        
        print(f"Cracked a total of {len(self.cracked)} out of {len(self.pkts)} encrypted packets.")


def read_pcap(pcap_filepath):
    """
    Reads packets in pcap/pcapng files
    """
    pcap = rdpcap(pcap_filepath)
    pkts = list()
    for pkt in pcap:
        # Filters for OSPF packets with auth data
        if OSPF_Hdr in pkt and pkt[OSPF_Hdr].authtype == 2 and pkt[OSPF_Hdr].authdatalen == 16:
            pkt_len = pkt[OSPF_Hdr].len * 2
            authdata_len = pkt[OSPF_Hdr].authdatalen * 2
            pkt_data = raw(pkt[OSPF_Hdr]).hex()
            pkt_tuple = (pkt_data[:pkt_len], pkt_data[pkt_len:pkt_len + authdata_len])
            pkts.append(pkt_tuple)

    # Writes netmd5 hashes to a file

    # if len(pkts) > 0:
    #     with open(os.path.splitext(pcap_filepath)[0] + '.txt', 'w') as file:
    #         [file.write(f'$netmd5${pkt[0]}${pkt[1]}\n') for pkt in pkts]

    return pkts


if __name__ == "__main__":
    load_contrib('ospf')
    pkts = read_pcap('test.pcapng')

    # rockyou test
    c = MD5_Cracker('rockyou', pkts)
    c.crack('rock.txt')

    # bruteforce test
    c = MD5_Cracker('bruteforce', pkts)
    c.crack()
