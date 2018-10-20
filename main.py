# database 				=> http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
# pip install pygeoip 	=> this repo deprecated yet still works
# pip install dpkt 		=> packet creation / parsing, with definitions for the basic TCP/IP protocols

import pygeoip as pg
import dpkt
import socket


GEO_IP_DATABASE_URL = '/opt/geoip/Geo.dat'


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


def main():
	# {'city': u'Istanbul', 'region_code': u'34', 'area_code': 0, 'time_zone': 'Asia/Istanbul', 'dma_code': 0, 'metro_code': None, 'country_code3': 'TUR', 'latitude': 41.01859999999999, 'postal_code': None, 'longitude': 28.964699999999993, 'country_code': 'TR', 'country_name': 'Turkey', 'continent': 'EU'}
	print(getIpInfo('212.2.212.131'))


if __name__ == '__main__':
	main()
