# database => http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
# pip install pygeoip => this repo deprecated yet still works

import pygeoip as pg

### GLOBAL
GEO_IP_DATABASE_URL = '/opt/geoip/Geo.dat'

### FUNCTIONS
def getIpInfo(targetIp):
	return pg.GeoIP(GEO_IP_DATABASE_URL).record_by_name(targetIp)


def main():
	print(getIpInfo('213.234.267.229'))


if __name__ == '__main__':
	main()
