#!/usr/bin/python
# = = = = = = = = = = = = = = = = = = = = = = =
# =       Copyright (C) 2010 uib GmbH         =
# =           http://www.uib.de               =
# =          All rights reserved.             =
# = = = = = = = = = = = = = = = = = = = = = = =

import os, sys, socket, re, shutil, getopt, pwd, grp

from OPSI.Logger import *
from OPSI.Types import *
from OPSI.System import *
from OPSI.Util.File import *

logger = Logger()
logger.setConsoleLevel(LOG_ERROR)
logger.setConsoleColor(True)

SMB_CONF         = u'/etc/samba/smb.conf'
SMB_INIT         = u'/etc/init.d/samba'
DHCPD_CONF       = u'/etc/dhcp3/dhcpd.conf'
DHCPD_INIT       = u'/etc/init.d/dhcp3-server'
SUDOERS          = u'/etc/sudoers'
OPSICONFD_USER   = u'opsiconfd'
ADMIN_GROUP      = u'opsiadmin'
CLIENT_USER      = u'pcpatch'
FILE_ADMIN_GROUP = u'pcpatch'

def getSysConfig():
	logger.notice(u"Getting current system config")
	sysConfig = {}
	try:
		sysConfig['fqdn'] = forceHostId(socket.getfqdn())
	except:
		raise Exception(u"Failed to get fully qualified domain name, got '%s'" % socket.getfqdn())
	
	sysConfig['hostname'] = sysConfig['fqdn'].split(u'.')[0]
	sysConfig['domain'] = u'.'.join(sysConfig['fqdn'].split(u'.')[1:])
	sysConfig['ip'] = socket.gethostbyname(sysConfig['fqdn'])
	if sysConfig['ip'].split(u'.')[0] in ('127', '169'):
		sysConfig['ip'] = None
	
	for device in getEthernetDevices():
		devconf = getNetworkDeviceConfig(device)
		if devconf['ipAddress'] and devconf['ipAddress'].split(u'.')[0] not in ('127', '169'):
			if not sysConfig['ip']:
				sysConfig['ip'] = devconf['ipAddress']
			if (sysConfig['ip'] == devconf['ipAddress']):
				sysConfig['netmask'] = devconf['netmask']
				break
	
	if not sysConfig['ip']:
		raise Exception(u"Failed to get a valid ip address for fqdn '%s'" % sysConfig['fqdn'])
	
	if not sysConfig.get('netmask'):
		sysConfig['netmask'] = u'255.255.255.0'
	
	sysConfig['broadcast'] = u''
	sysConfig['subnet']    = u''
	for i in range(4):
		if sysConfig['broadcast']: sysConfig['broadcast'] += u'.'
		if sysConfig['subnet']:    sysConfig['subnet']    += u'.'
		sysConfig['subnet']    += u'%d' % ( int(sysConfig['ip'].split(u'.')[i]) & int(sysConfig['netmask'].split(u'.')[i]) )
		sysConfig['broadcast'] += u'%d' % ( int(sysConfig['ip'].split(u'.')[i]) | int(sysConfig['netmask'].split(u'.')[i]) ^ 255 )
	
	sysConfig['winDomain'] = u''
	if os.path.exists(SMB_CONF):
		f = open(SMB_CONF)
		for line in f.readlines():
			match = re.search('^\s*workgroup\s*=\s*(\S+)\s*$', line)
			if match:
				sysConfig['winDomain'] = match.group(1).upper()
				break
		f.close()
	
	logger.notice(u"System information:")
	logger.notice(u"   ip address : %s" % sysConfig['ip'])
	logger.notice(u"   netmask    : %s" % sysConfig['netmask'])
	logger.notice(u"   subnet     : %s" % sysConfig['subnet'])
	logger.notice(u"   broadcast  : %s" % sysConfig['broadcast'])
	logger.notice(u"   fqdn       : %s" % sysConfig['fqdn'])
	logger.notice(u"   hostname   : %s" % sysConfig['hostname'])
	logger.notice(u"   domain     : %s" % sysConfig['domain'])
	logger.notice(u"   win domain : %s" % sysConfig['winDomain'])
	
	return sysConfig


def configureSamba():
	logger.notice(u"Configuring samba")
	
	f = open(SMB_CONF)
	lines = f.readlines()
	f.close()
	newlines = []
	depotShareFound = False
	configShareFound = False
	workbenchShareFound = False
	confChanged = False
	
	for i in range(len(lines)):
		if (lines[i].lower().strip() == '; load opsi shares') and ((i+1) < len(lines)) and (lines[i+1].lower().strip() == 'include = /etc/samba/share.conf'):
			i += 1
			confChanged = True
			continue
		if   (lines[i].lower().strip() == '[opt_pcbin]'):
			depotShareFound = True
		elif (lines[i].lower().strip() == '[opsi_config]'):
			configShareFound = True
		elif (lines[i].lower().strip() == '[opsi_workbench]'):
			workbenchShareFound = True
		newlines.append(lines[i])
	
	if not depotShareFound:
		logger.notice(u"   Adding share [opt_pcbin]")
		confChanged = True
		newlines.append(u"[opt_pcbin]\n")
		newlines.append(u"   available = yes\n")
		newlines.append(u"   comment = opsi depot share\n")
		newlines.append(u"   path = /opt/pcbin\n")
		newlines.append(u"   oplocks = no\n")
		newlines.append(u"   level2 oplocks = no\n")
		newlines.append(u"   writeable = yes\n")
		newlines.append(u"   invalid users = root\n")
	
	if not configShareFound:
		logger.notice(u"   Adding share [opsi_config]")
		confChanged = True
		newlines.append(u"[opsi_config]\n")
		newlines.append(u"   available = yes\n")
		newlines.append(u"   comment = opsi config share\n")
		newlines.append(u"   path = /var/lib/opsi/config\n")
		newlines.append(u"   writeable = yes\n")
		newlines.append(u"   invalid users = root\n")
	
	if not workbenchShareFound:
		logger.notice(u"   Adding share [opsi_workbench]")
		confChanged = True
		newlines.append(u"[opsi_workbench]\n")
		newlines.append(u"   available = yes\n")
		newlines.append(u"   comment = opsi workbench\n")
		newlines.append(u"   path = /home/opsiproducts\n")
		newlines.append(u"   writeable = yes\n")
		newlines.append(u"   invalid users = root\n")
		newlines.append(u"   create mask = 0660\n")
		newlines.append(u"   directory mask = 0770\n")
	
	if confChanged:
		logger.notice(u"   Creating backup of %s" % SMB_CONF)
		shutil.copy(SMB_CONF, SMB_CONF + u'.' + time.strftime("%Y-%m-%d_%H:%M"))
		
		logger.notice(u"   Writing new smb.conf")
		f = open(SMB_CONF, 'w')
		lines = f.writelines(newlines)
		f.close()
		
		logger.notice(u"   Reloading samba")
		execute(u'%s reload' % SMB_INIT)
		
	
def configureDHCPD(config):
	logger.notice(u"Configuring dhcpd")
	
	dhcpdConf = DHCPDConfFile(DHCPD_CONF)
	dhcpdConf.parse()
	
	confChanged = False
	if dhcpdConf.getGlobalBlock().getParameters_hash().get('use-host-decl-names', False):
		logger.info(u"   use-host-decl-names already enabled")
	else:
		confChanged = True
		dhcpdConf.getGlobalBlock().addComponent(
			DHCPDConf_Parameter(
				startLine 	= -1,
				parentBlock 	= dhcpdConf.getGlobalBlock(),
				key 		= 'use-host-decl-names',
				value 		= True ) )
	
	subnets = dhcpdConf.getGlobalBlock().getBlocks('subnet', recursive = True)
	if not subnets:
		confChanged = True
		logger.notice(u"   No subnets found, adding subnet")
		dhcpdConf.getGlobalBlock().addComponent(
			DHCPDConf_Block(
				startLine 	= -1,
				parentBlock 	= dhcpdConf.getGlobalBlock(),
				type 		= 'subnet',
				settings 	= ['subnet', sysConfig['subnet'], 'netmask', sysConfig['netmask']] ) )
	
	for subnet in dhcpdConf.getGlobalBlock().getBlocks('subnet', recursive = True):
		logger.info(u"   Found subnet %s/%s" % (subnet.settings[1], subnet.settings[3]))
		groups = subnet.getBlocks('group')
		if not groups:
			confChanged = True
			logger.notice(u"      No groups found, adding group")
			subnet.addComponent(
				DHCPDConf_Block(
					startLine 	= -1,
					parentBlock 	= subnet,
					type 		= 'group',
					settings 	= ['group'] ) )
		for group in subnet.getBlocks('group'):
			logger.info(u"      Configuring group")
			params = group.getParameters_hash(inherit = 'global')
			if params.get('next-server'):
				logger.info(u"         next-server already set")
			else:
				confChanged = True
				group.addComponent(
					DHCPDConf_Parameter(
						startLine 	= -1,
						parentBlock 	= group,
						key 		= 'next-server',
						value 		= sysConfig['ip'] ) )
				logger.notice(u"   next-server set to %s" % sysConfig['ip'])
			if params.get('filename'):
				logger.info(u"         filename already set")
			else:
				confChanged = True
				group.addComponent(
					DHCPDConf_Parameter(
						startLine 	= -1,
						parentBlock 	= group,
						key 		= 'filename',
						value 		= 'linux/pxelinux.0' ) )
				logger.notice(u"         filename set to linux/pxelinux.0")
	
	if confChanged:
		logger.notice(u"   Creating backup of %s" % DHCPD_CONF)
		shutil.copy(DHCPD_CONF, DHCPD_CONF + u'.' + time.strftime("%Y-%m-%d_%H:%M"))
		
		logger.notice(u"   Writing new %s" % DHCPD_CONF)
		dhcpdConf.generate()
		
		logger.notice(u"   Restarting dhcpd")
		execute(u'%s restart' % DHCPD_INIT)
	
	logger.notice(u"Configuring sudoers")
	
	found = False
	f = open(SUDOERS)
	lines = []
	for line in f.readlines():
		if (line.find('%s restart' % DHCPD_INIT) != -1):
			found = True
		lines.append(line)
	f.close()
	if not found:
		logger.notice(u"   Creating backup of %s" % SUDOERS)
		shutil.copy(SUDOERS, SUDOERS + u'.' + time.strftime("%Y-%m-%d_%H:%M"))
		
		logger.notice(u"   Adding sudoers entry for dhcpd restart")
		lines.append(u"opsiconfd ALL=NOPASSWD: %s restart\n")
		logger.notice(u"   Writing new %s" % SUDOERS)
		f = open(SUDOERS, 'w')
		f.writelines(lines)
		f.close()

def configureClientUser():
	logger.notice(u"Configuring client user %s" % CLIENT_USER)
	
	clientUserUid  = pwd.getpwnam(CLIENT_USER)[2]
	clientUserHome = pwd.getpwnam(CLIENT_USER)[5]
	adminGroupGid  = grp.getgrnam(ADMIN_GROUP)[2]
	
	
	sshDir = os.path.join(clientUserHome, '.ssh')
	
	if os.path.exists(sshDir):
		shutil.rmtree(sshDir)
	
	idRsa = os.path.join(sshDir, u'id_rsa')
	idRsaPub = os.path.join(sshDir, u'id_rsa.pub')
	authorizedKeys = os.path.join(sshDir, u'authorized_keys')
	if not os.path.exists(sshDir):
		os.mkdir(sshDir, 0750)
		os.chown(sshDir, clientUserUid, adminGroupGid)
	if not os.path.exists(idRsa):
		logger.notice(u"   Creating RSA private key for user %s in '%s'" % (CLIENT_USER, idRsa))
		execute(u"%s -N '' -t rsa -f %s" % ( which('ssh-keygen'), idRsa))
		os.chmod(idRsa, 0640)
		os.chown(idRsa, clientUserUid, adminGroupGid)
		os.chmod(idRsaPub, 0644)
		os.chown(idRsaPub, clientUserUid, adminGroupGid)
	if not os.path.exists(authorizedKeys):
		f = open(idRsaPub, 'r')
		f2 = open(authorizedKeys, 'w')
		f2.write(f.read())
		f2.close()
		f.close()
		os.chmod(authorizedKeys, 0600)
		os.chown(authorizedKeys, clientUserUid, adminGroupGid)

def setRights():
	logger.notice(u"Setting rights")
	
	opsiconfdUid      = pwd.getpwnam(OPSICONFD_USER)[2]
	adminGroupGid     = grp.getgrnam(ADMIN_GROUP)[2]
	fileAdminGroupGid = grp.getgrnam(FILE_ADMIN_GROUP)[2]
	
	files = []
	for dirname in (u'/etc/opsi/backends', u'/etc/opsi/backendManager', u'/etc/opsi/backendManager/extend.d'):
		if os.path.exists(dirname):
			logger.info(u"   Setting rights on directory '%s'" % dirname)
			os.chown(dirname, opsiconfdUid, adminGroupGid)
			os.chmod(dirname, 0770)
			for f in os.listdir(dirname):
				if os.path.isfile(os.path.join(dirname, f)):
					files.append(os.path.join(dirname, f))
	for filename in files:
		if os.path.exists(filename):
			logger.info(u"   Setting rights on file '%s'" % filename)
			os.chown(filename, opsiconfdUid, adminGroupGid)
			os.chmod(filename, 0660)
	

def usage():
	print u"\nUsage: %s [options]" % os.path.basename(sys.argv[0])
	print u""
	print u"Options:"
	print u"   -h          show this help"
	print u"   -l          log-level 0..9"
	print u""

def main():
	if (os.geteuid() != 0):
		raise Exception(u"This script must be startet as root")
	
	try:
		(opts, args) = getopt.getopt(sys.argv[1:], "hl:")
	
	except getopt.GetoptError:
		usage()
		sys.exit(1)
	
	for (opt, arg) in opts:
		if   (opt == "-h"):
			usage()
			return
		elif (opt == "-l"):
			logger.setConsoleLevel(int(arg))
	
	sysConfig = getSysConfig()
	configureSamba()
	configureDHCPD(sysConfig)
	configureClientUser()
	setRights()
	
if (__name__ == "__main__"):
	exception = None
	try:
		main()
	except SystemExit, e:
		pass
	
	except Exception, e:
		exception = e
	
	if exception:
		logger.logException(exception)
		print >> sys.stderr, u"\nERROR: %s\n" % exception
		sys.exit(1)
	sys.exit(0)















