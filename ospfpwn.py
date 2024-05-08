import argparse
from scapy.all import load_contrib
from attacks.sniff_ospf import sniff_ospf
from attacks.md5_cracker import MD5_Cracker, read_pcap


def banner():
    print("""
   ____    _____  _____   ______                      
  / __ \  / ____||  __ \ |  ____|                     
 | |  | || (___  | |__) || |__  _ __ __      __ _ __  
 | |  | | \___ \ |  ___/ |  __|| '_ \\\ \ /\ / /| '_ \ 
 | |__| | ____) || |     | |   | |_) |\ V  V / | | | |
  \____/ |_____/ |_|     |_|   | .__/  \_/\_/  |_| |_|
                               | |                    
                               |_|                    
    """)


def parse_arguments():
    parser = argparse.ArgumentParser(description='OSPFpwn', formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=50))

    # Add arguments
    parser.add_argument('-a', '--attack', type=int, help='Enter attack option', required=True)
    parser.add_argument('-i', '--iface', type=str, help='Attack Interface')
    parser.add_argument('-o', '--output', type=str, help='output file')
    parser.add_argument('-f', '--file', type=str, help='Pcap file')
    parser.add_argument('-b', '--brute', action='store_true', help='Brute-force for cracking')
    parser.add_argument('-w', '--wordlist', type=str, help='Wordlist for brute-force')

    args = parser.parse_args()

    # Validate arguments
    if args.attack not in [1, 2]:
        parser.error("Invalid attack option : -a {1,2}")
    elif args.attack == 1 and not args.iface:
        parser.error("Required argument(s): -i <interface> -o <outfile>")
    elif args.attack == 2:
        if not args.file:
            parser.error("Required argument(s): -f <path/to/pcap> [-w <path/to/wordlist | -b]")
        elif not (args.wordlist or args.brute):
            parser.error("Required argument(s): [-w <path/to/wordlist | -b]")

    return args


def main():
    load_contrib("ospf")
    args = parse_arguments()
    if not args.attack:
        banner()

    # Start Attack
    if args.attack == 1:
        sniff_ospf(args.iface, args.output)
    elif args.attack == 2:
        cracker = MD5_Cracker('bruteforce' if args.brute else 'rockyou', read_pcap(args.file))
        cracker.crack(args.wordlist if args.wordlist else None)


if __name__ == "__main__":
    main()
