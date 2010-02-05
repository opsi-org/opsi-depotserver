#!/usr/bin/python
# = = = = = = = = = = = = = = = = = = = = = = =
# =       Copyright (C) 2010 uib GmbH         =
# =           http://www.uib.de               =
# =          All rights reserved.             =
# = = = = = = = = = = = = = = = = = = = = = = =

import os, sys, socket, re

from OPSI.Logger import *
from OPSI.Types import *
from OPSI.System import *

logger = Logger()
logger.setConsoleLevel(LOG_NOTICE)

SMB_CONF = u'/etc/samba/smb.conf'

def getConfig():
	config = {}
	try:
		config['fqdn'] = forceHostId(socket.getfqdn())
	except:
		raise Exception(u"Failed to get fully qualified domain name, got '%s'" % socket.getfqdn())
	
	config['hostname'] = config['fqdn'].split(u'.')[0]
	config['domain'] = u'.'.join(config['fqdn'].split(u'.')[1:])
	config['ip'] = socket.gethostbyname(config['fqdn'])
	if config['ip'].split(u'.')[0] in ('127', '169'):
		config['ip'] = None
	
	for device in getEthernetDevices():
		devconf = getNetworkDeviceConfig(device)
		if devconf['ipAddress'] and devconf['ipAddress'].split(u'.')[0] not in ('127', '169'):
			if not config['ip']:
				config['ip'] = devconf['ipAddress']
			if (config['ip'] == devconf['ipAddress']):
				config['netmask'] = devconf['netmask']
				break
	
	if not config['ip']:
		raise Exception(u"Failed to get a valid ip address for fqdn '%s'" % config['fqdn'])
	
	if not config.get('netmask'):
		config['netmask'] = u'255.255.255.0'
	
	config['broadcast'] = u''
	config['subnet']    = u''
	for i in range(4):
		if config['broadcast']:	config['broadcast'] += u'.'
		if config['subnet']:    config['subnet']    += u'.'
		config['subnet']    += u'%d' % ( int(config['ip'].split(u'.')[i]) & int(config['netmask'].split(u'.')[i]) )
		config['broadcast'] += u'%d' % ( int(config['ip'].split(u'.')[i]) | int(config['netmask'].split(u'.')[i]) ^ 255 )
	
	config['winDomain'] = u''
	if os.path.exists(SMB_CONF):
		f = open(SMB_CONF)
		for line in f.readlines():
			match = re.search('^\s*workgroup\s*=\s*(\S+)\s*$', line)
			if match:
				config['winDomain'] = match.group(1).upper()
				break
		f.close()
	
	logger.notice(u"System information")
	logger.notice(u"   ip address : %s" % config['ip'])
	logger.notice(u"   netmask    : %s" % config['netmask'])
	logger.notice(u"   subnet     : %s" % config['subnet'])
	logger.notice(u"   broadcast  : %s" % config['broadcast'])
	logger.notice(u"   fqdn       : %s" % config['fqdn'])
	logger.notice(u"   hostname   : %s" % config['hostname'])
	logger.notice(u"   domain     : %s" % config['domain'])
	logger.notice(u"   win domain : %s" % config['winDomain'])
	
	
getConfig()












