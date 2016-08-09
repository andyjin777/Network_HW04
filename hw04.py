from scapy.all import IP, sniff
from scapy.layers import http

def process_tcp_packet(packet):
    if not packet.haslayer(http.HTTPRequest):
        return
    http_layer = packet.getlayer(http.HTTPRequest)
    ip_layer = packet.getlayer(IP)
    a = 'http://{1[Host]}'.format(ip_layer.fields, http_layer.fields)
    if arr.count(a) == 1 : 
    	fp.write('error site !! : '+a+'\n')

f = open("./mal_site.txt", 'r')
fp = open("./log.txt", 'w')
arr = []
while 1 :
	line = f.readline()
	if not line : break
	temp = line.rstrip('\n')
	arr.append(temp)
f.close()

sniff(filter='tcp', prn=process_tcp_packet)
