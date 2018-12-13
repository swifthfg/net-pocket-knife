# database 				=> http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
# pip install pygeoip 	=> this repo deprecated yet still works
# pip install dpkt 		=> packet creation / parsing, with definitions for the basic TCP/IP protocols
# pip install scapy		=> packet creation / parsing
# pip install IPy		=> IPTEST


import pygeoip as pg
import dpkt
import socket
from scapy.all import *
from IPy import IP as IPTEST


GEO_IP_DATABASE_URL = '/opt/geoip/Geo.dat'
MAX_HOP_DIFFERENCE = 5 # threshold for ttl difference


def getIpInfo(targetIp):
	return pg.GeoIP(GEO_IP_DATABASE_URL).record_by_name(targetIp)


def analysePcap(pcapFilePath):
	pcapFileHandler = open(pcapFilePath)
	pcapInfo = dpkt.pcap.Reader(pcapFileHandler)
	for (timestamp, packet) in pcapInfo:
		try:
			eth = dpkt.ethernet.Ethernet(packet) # physical and data link layers
			ip = eth.data
			source = socket.inet_ntoa(ip.src)
			destination = socket.inet_ntoa(ip.dst)
			ipInfoSrc = getIpInfo(source)
			ipInfoDst = getIpInfo(destination)

			print 'From: ' + source + ' to: ' + destination + '\n'
			print ipInfoSrc['city'] + ', ' + ipInfoSrc['country_code3'] + ' --> ' + ipInfoDst['city'] + ', ' + ipInfoDst['country_code3']
			print '---------------------------------------\n'
		except:
			pass


def checkTTL(ipSrc, ttl):
	ttlValues = {}
	if IPTEST(ipSrc).iptype == 'PRIVATE':
		return
	if ipSrc not in ttlValues:
		packet = sr1(IP(dst=ipSrc) / ICMP(), retry=0, timeout=1, verbose=0)
		ttlValues[ipSrc] = packet.ttl
	if abs(int(ttl) - int(ttlValues[ipSrc])) > MAX_HOP_DIFFERENCE:
		print 'Detected possible spoofed packet from: ' + ipSrc
		print 'TTL: ' + ttl + ' Actual TTL: ' + str(ttlValues[ipSrc])


def watchTTL(packet):
	try:
		if packet.haslayer(IP):
			ipSrc = packet.getlayer(IP).src
			ttl = str(packet.ttl)
			checkTTL(ipSrc, ttl)
			# print 'Packet received from: ' + ipSrc + ' with TTL: ' + ttl
	except:
		pass


def simpleTCPClient():
	import socket
	targetHost = "www.google.com"
	targetPort = 80

	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client.connect((targetHost, targetPort))
	client.send('GET / HTTP/1.1\nHost: google.com\n\n')
	response = client.recv(4096)

	print response


def main():
	# {'city': u'Istanbul', 'region_code': u'34', 'area_code': 0, 'time_zone': 'Asia/Istanbul', 'dma_code': 0, 'metro_code': None, 'country_code3': 'TUR', 'latitude': 41.01859999999999, 'postal_code': None, 'longitude': 28.964699999999993, 'country_code': 'TR', 'country_name': 'Turkey', 'continent': 'EU'}
	# print(getIpInfo('212.2.212.131'))
	# sniff(prn=watchTTL, store=0)
	simpleTCPClient()


if __name__ == '__main__':
	main()
