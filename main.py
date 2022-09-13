import scapy.all as scapy
import gzip
from packets.OpCodes_Steam import OpCodes_Steam

with open('resources/xor_Steam.bin', 'rb') as f:
    xorBytes = gzip.decompress(f.read())
    xorKey = list(xorBytes)

def processPacket(packet):
    p = bytes(packet[scapy.TCP].payload)
    packetSize = int.from_bytes(p[0:1], "little")
    if (len(p)<6): return
    if (p[5] != 1 | packetSize < 7 | packetSize>len(p)): return
    seed = int.from_bytes(p[2:4], "little")
    if seed in OpCodes_Steam._value2member_map_: print(OpCodes_Steam(seed).name)
    payload = p[6:][0:(packetSize-6)]
    payload_decrypted = xor_cipher(payload, seed, xorKey)
    #print(str(decrypted_payload))

def xor_cipher(data, seed, xorKey):
    decrypted_data = []
    for i in range (0, len(data)-1):
        decrypted_data.append(data[i] ^ xorKey[(seed) % len(xorKey)])
        seed+=1
    return decrypted_data

#1 - Find Interface Name
#for interface in scapy.interfaces.get_working_ifaces():
#    print(interface.name + " " + interface.ip + " " + interface.description)

#2 - Start Sniffer
scapy.sniff(iface="Wi-Fi",  filter='tcp src port 6040', prn=processPacket, store=0)



