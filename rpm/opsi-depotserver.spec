#
# spec file for package opsi-depotserver
#
# Copyright (c) 2008 uib GmbH.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#

Name:           opsi-depotserver
Requires:       python-opsi opsiconfd opsipxeconfd opsi-utils opsi-linux-bootimage samba dhcp-server sudo wget
Url:            http://www.opsi.org
License:        GPL v2 or later
Group:          Productivity/Networking/Opsi
AutoReqProv:    on
Version:        3.3
Release:        9
Summary:        opsi depotserver
%define tarname opsi-depotserver
Source:         %{tarname}-%{version}.tar.bz2
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildArch:      noarch

# ===[ description ]================================
%description
opsi depotserver

# ===[ debug_package ]==============================
%debug_package

# ===[ prep ]=======================================
%prep

# ===[ setup ]======================================
%setup

# ===[ build ]======================================
%build

# ===[ install ]====================================
%install
mkdir -p $RPM_BUILD_ROOT/opt/pcbin/install
mkdir -p $RPM_BUILD_ROOT/opt/pcbin/pcpatch
mkdir -p $RPM_BUILD_ROOT/opt/pcbin/utils
mkdir -p $RPM_BUILD_ROOT/home/opsiproducts
mkdir -p $RPM_BUILD_ROOT/var/log/opsi
mkdir -p $RPM_BUILD_ROOT/var/lib/opsi/audit
mkdir -p $RPM_BUILD_ROOT/var/lib/opsi/config/depots
mkdir -p $RPM_BUILD_ROOT/var/lib/opsi/config/templates
mkdir -p $RPM_BUILD_ROOT/var/lib/opsi/products
mkdir -p $RPM_BUILD_ROOT/var/lib/opsi/config/clients
install -m 0660 var/lib/opsi/config/templates/pcproto.ini $RPM_BUILD_ROOT/var/lib/opsi/config/templates/
install -m 0660 var/lib/opsi/config/global.ini $RPM_BUILD_ROOT/var/lib/opsi/config/

# ===[ clean ]======================================
%clean
rm -rf $RPM_BUILD_ROOT


# ===[ pre ]========================================
%pre
VERBOSE=true
HOSTNAME=`uname -n`
DOMAIN=`hostname -d`
FQDN=`hostname --fqdn`
IPADDRESS=`getent hosts $FQDN | cut -d' ' -f1`
[ "$IPADDRESS" = "127.0.0.2" ] && IPADDRESS=""

for iface in `ifconfig -a | grep "^[[:alnum:]]" | cut -d " " -f 1`; do
	ip=`ifconfig $iface | grep "\:[[:digit:]]*\." | sed "s/:/ /g" | awk '{ printf $3}'`
	NETMASK=`ifconfig $iface | grep "\:[[:digit:]]*\." | sed "s/:/ /g" | awk '{ printf $7}'`
	GATEWAY=`route -n | grep ^0.0.0.0 | awk '{ printf $2}'`
	if [ "$ip" != "" ]; then
		if [ "$IPADDRESS" = "" ]; then
			IPADDRESS="$ip"
		fi
		[ "$IPADDRESS" = "$ip" ] && break
	fi
done

[ "$NETMASK" = "" ] && NETMASK="255.255.225.0"

if [ "$IPADDRESS" != "" ]; then
	for part in 1 2 3 4; do
		I[$part]=$(echo $IPADDRESS | cut -d . -f $part)
		M[$part]=$(echo $NETMASK | cut -d . -f $part)
	done
	
	for part in 1 2 3 4; do
		N[$part]=$((${I[$part]} & ${M[$part]}))
		B[$part]=$((${N[$part]} | $((${M[$part]} ^255))))
	done
	
	SUBNET="${N[1]}.${N[2]}.${N[3]}.${N[4]}"
	BROADCAST="${B[1]}.${B[2]}.${B[3]}.${B[4]}"
fi

$VERBOSE && echo -e "\nAdding system users and groups..."

# add system group pcpatch and users pcpatch
$VERBOSE && echo "  -> Adding group pcpatch"
if [ -z "`getent group pcpatch`" ]; then
	groupadd -g 992 pcpatch
fi
	
$VERBOSE && echo "  -> Adding user pcpatch"
if [ -z "`getent passwd pcpatch`" ]; then
	useradd -u 992 -g 992 -d /opt/pcbin/pcpatch -s /bin/bash pcpatch
fi

$VERBOSE && echo "  -> Adding user opsiconfd"
if [ -z "`getent passwd opsiconfd`" ]; then
	useradd -u 993 -g 992 -d /var/lib/opsi -s /bin/bash opsiconfd
fi

writeDepotIni=false
if [ -e /var/lib/opsi/config/depots/$FQDN/depot.ini ]; then
	set +e
	grep '\[repository\]' /var/lib/opsi/config/depots/$FQDN/depot.ini >/dev/null 2>/dev/null	
	status=$?
	set -e
	if [ $status = 1 ]; then
		# Old version (before opsi 3.3) of ini file found
		writeDepotIni=true
	fi
else
	writeDepotIni=true
fi

if $writeDepotIni; then
	echo "Writing depot.ini"
	
	mkdir -p /var/lib/opsi/config/depots/$FQDN >/dev/null 2>/dev/null || true
	chmod -R 777 /var/lib/opsi
	
	echo "[depotshare]" 						>  /var/lib/opsi/config/depots/$FQDN/depot.ini
	echo "remoteurl = smb://$HOSTNAME/opt_pcbin/install"		>> /var/lib/opsi/config/depots/$FQDN/depot.ini
	echo "localurl = file:///opt/pcbin/install"			>> /var/lib/opsi/config/depots/$FQDN/depot.ini
	echo ""								>> /var/lib/opsi/config/depots/$FQDN/depot.ini
	echo "[depotserver]"						>> /var/lib/opsi/config/depots/$FQDN/depot.ini
	echo "notes ="							>> /var/lib/opsi/config/depots/$FQDN/depot.ini
	echo "network = $SUBNET/$NETMASK"				>> /var/lib/opsi/config/depots/$FQDN/depot.ini
	echo "description ="						>> /var/lib/opsi/config/depots/$FQDN/depot.ini
	echo ""								>> /var/lib/opsi/config/depots/$FQDN/depot.ini
	echo "[repository]"						>> /var/lib/opsi/config/depots/$FQDN/depot.ini
	echo "remoteurl = webdavs://$FQDN:4447/products"		>> /var/lib/opsi/config/depots/$FQDN/depot.ini
	echo "localurl = file:///var/lib/opsi/products"		>> /var/lib/opsi/config/depots/$FQDN/depot.ini
	echo "maxbandwidth = 0"						>> /var/lib/opsi/config/depots/$FQDN/depot.ini
	
	chmod 664 /var/lib/opsi/config/depots/$FQDN/depot.ini
fi

mkdir -p /var/lib/opsi/products
chown -R opsiconfd:pcpatch /var/lib/opsi
chmod 2750 /var/lib/opsi
chmod 2770 /var/lib/opsi/products
chmod 0660 /var/lib/opsi/products/* >/dev/null 2>/dev/null || true

# ===[ post ]=======================================
%post
VERBOSE=true
SAMBA_CONF="/etc/samba/smb.conf"
SAMBA_INIT="/etc/init.d/smb"
DHCPD_CONF="/etc/dhcpd.conf"
DHCPD_INIT="/etc/init.d/dhcpd"
CONFIGURE_SAMBA="true"
CONFIGURE_DHCPD="true"
PCPATCH_PASSWORD=`< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c12`

HOSTNAME=`uname -n`
DOMAIN=`hostname -d`
FQDN=`hostname --fqdn`
IPADDRESS=`getent hosts $FQDN | cut -d' ' -f1`

for iface in `ifconfig -a | grep "^[[:alnum:]]" | cut -d " " -f 1`; do
	ip=`ifconfig $iface | grep "\:[[:digit:]]*\." | sed "s/:/ /g" | awk '{ printf $3}'`
	NETMASK=`ifconfig $iface | grep "\:[[:digit:]]*\." | sed "s/:/ /g" | awk '{ printf $7}'`
	GATEWAY=`route -n | grep ^0.0.0.0 | awk '{ printf $2}'`
	if [ "$ip" != "" ]; then
	if [ "$IPADDRESS" = "" ]; then
		IPADDRESS="$ip"
	fi
	[ "$IPADDRESS" = "$ip" ] && break
	fi
done

[ "$NETMASK" = "" ] && NETMASK="255.255.225.0"

if [ "$IPADDRESS" != "" ]; then
	for part in 1 2 3 4; do
		I[$part]=$(echo $IPADDRESS | cut -d . -f $part)
		M[$part]=$(echo $NETMASK | cut -d . -f $part)
	done
	
	for part in 1 2 3 4; do
		N[$part]=$((${I[$part]} & ${M[$part]}))
		B[$part]=$((${N[$part]} | $((${M[$part]} ^255))))
	done
	
	SUBNET="${N[1]}.${N[2]}.${N[3]}.${N[4]}"
	BROADCAST="${B[1]}.${B[2]}.${B[3]}.${B[4]}"
fi

WINDOMAIN=`grep -i ^[[:space:]]*workgroup $SAMBA_CONF | cut -d'=' -f 2 | sed s'/ //g'`

$VERBOSE && echo -e "\nSystem information"
$VERBOSE && echo "  -> IP-Address: $IPADDRESS"
$VERBOSE && echo "  -> Broadcast: $BROADCAST"
$VERBOSE && echo "  -> Netmask: $NETMASK"
$VERBOSE && echo "  -> Subnet: $SUBNET"
$VERBOSE && echo "  -> Gateway: $GATEWAY"
$VERBOSE && echo "  -> Hostname: $HOSTNAME"
$VERBOSE && echo "  -> Domain: $DOMAIN"
$VERBOSE && echo "  -> Fqdn: $FQDN"
$VERBOSE && echo "  -> Windomain: $WINDOMAIN"

if [ `echo $FQDN | sed 's/\./ /g' | wc -w` -le 2 ]; then
	echo -e "\nThe hostname $FQDN returned by 'hostname --fqdn' is not a fully qualified domain name"
	echo "Opsi needs a fully qualified domain name in the form of <hostname>.<domain>.<tld>"
	exit 1
fi

if [ -f /var/lib/opsi/config/global.ini ]; then
	set +e
	grep "@HOSTNAME@" /var/lib/opsi/config/global.ini >/dev/null 2>/dev/null	
	status=$?
	set -e
	if [ $status = 0 ]; then
		cp /var/lib/opsi/config/global.ini /var/lib/opsi/config/global.ini.tmp
		cat /var/lib/opsi/config/global.ini.tmp | sed "s/@HOSTNAME@/$HOSTNAME/g" > /var/lib/opsi/config/global.ini
		rm /var/lib/opsi/config/global.ini.tmp
	fi
	set +e
	grep "@WINDOMAIN@" /var/lib/opsi/config/global.ini >/dev/null 2>/dev/null	
	status=$?
	set -e
	if [ $status = 0 ]; then
		cp /var/lib/opsi/config/global.ini /var/lib/opsi/config/global.ini.tmp
		cat /var/lib/opsi/config/global.ini.tmp | sed "s/@WINDOMAIN@/$WINDOMAIN/g" > /var/lib/opsi/config/global.ini
		rm /var/lib/opsi/config/global.ini.tmp
	fi
	set +e
	grep "@FQDN@" /var/lib/opsi/config/global.ini >/dev/null 2>/dev/null	
	status=$?
	set -e
	if [ $status = 0 ]; then
		cp /var/lib/opsi/config/global.ini /var/lib/opsi/config/global.ini.tmp
		cat /var/lib/opsi/config/global.ini.tmp | sed "s/@FQDN@/$FQDN/g" > /var/lib/opsi/config/global.ini
		rm /var/lib/opsi/config/global.ini.tmp
	fi
	set +e
	grep "@IPADDRESS@" /var/lib/opsi/config/global.ini >/dev/null 2>/dev/null	
	status=$?
	set -e
	if [ $status = 0 ]; then
		cp /var/lib/opsi/config/global.ini /var/lib/opsi/config/global.ini.tmp
		cat /var/lib/opsi/config/global.ini.tmp | sed "s/@IPADDRESS@/$IPADDRESS/g" > /var/lib/opsi/config/global.ini
		rm /var/lib/opsi/config/global.ini.tmp
	fi
fi

if ! [ -e /var/lib/opsi/config/depots/$FQDN ]; then
	mkdir -p /var/lib/opsi/config/depots/$FQDN
fi

# file permissions
$VERBOSE && echo -e "\nSetting permissions..."
chown -R opsiconfd:pcpatch /etc/opsi/backendManager.d
chmod 0660 /etc/opsi/backendManager.d/*
chown -R opsiconfd:pcpatch /opt/pcbin/pcpatch
chmod 2770 /opt/pcbin/pcpatch
chown -R opsiconfd:pcpatch /opt/pcbin/utils
chmod 2770 /opt/pcbin/utils
chown -R opsiconfd:pcpatch /opt/pcbin/install
chmod 2770 /opt/pcbin/install
chown -R opsiconfd:pcpatch /tftpboot/linux
chmod 2775 /tftpboot/linux
chmod 2775 /tftpboot/linux/pxelinux.cfg
find /tftpboot/linux -type f -exec chmod 664 {} \;
chown -R opsiconfd:pcpatch /var/lib/opsi
chmod 2750 /var/lib/opsi
# for ssh public key authentification to work rights on /var/lib/opsi have to be pcatch:pcpatch 750
chown pcpatch /var/lib/opsi
chmod 2770 /var/lib/opsi/products
chmod 0660 /var/lib/opsi/products/* >/dev/null 2>/dev/null || true
chmod 2770 /var/lib/opsi/config
chmod 2770 /var/lib/opsi/config/clients
chmod 2770 /var/lib/opsi/config/templates
chmod 2770 /var/lib/opsi/config/depots
chmod 2770 -R /var/lib/opsi/config/depots
find /var/lib/opsi/config/depots -type f -exec chmod 660 {} \;
chmod 2770 /var/lib/opsi/audit
chmod 0660 /var/lib/opsi/audit/* >/dev/null 2>/dev/null || true
chmod 0660 /var/lib/opsi/config/templates/pcproto.ini
chmod 0660 /var/lib/opsi/config/global.ini
chown opsiconfd:pcpatch /var/log/opsi
chmod 2770 /var/log/opsi
chown pcpatch:pcpatch /home/opsiproducts
chmod 2770 /home/opsiproducts

if [ "$CONFIGURE_SAMBA" = "true" ]; then
	$VERBOSE && echo -e "\nConfiguring samba..."	
	if [ -f $SAMBA_CONF ]; then
		# Removing include created by opsi-depotserver < 3.3
		cp $SAMBA_CONF $SAMBA_CONF.opsi-configure
		cat $SAMBA_CONF.opsi-configure \
			| grep -v '; load opsi shares' \
			| grep -v 'include = /etc/samba/share.conf' \
			> $SAMBA_CONF
		rm $SAMBA_CONF.opsi-configure
		
		$VERBOSE && echo "  -> Testing if share [opt_pcbin] already exists"
		set +e
		grep "^\[opt_pcbin\]" $SAMBA_CONF >/dev/null 2>/dev/null	
		status=$?
		set -e
		if [ $status = 0 ]; then
			$VERBOSE && echo "      * share exists"
		else
			$VERBOSE && echo "      * adding share"
			echo "" 				>> $SAMBA_CONF
			echo "[opt_pcbin]" 			>> $SAMBA_CONF
			echo " available = yes" 		>> $SAMBA_CONF
			echo " comment = opsi depot share" 	>> $SAMBA_CONF
			echo " path = /opt/pcbin" 		>> $SAMBA_CONF
			echo " oplocks = no" 			>> $SAMBA_CONF
			echo " level2 oplocks = no"  		>> $SAMBA_CONF
			echo " writeable = yes" 		>> $SAMBA_CONF
			echo " invalid users = root" 		>> $SAMBA_CONF
		fi
		
		$VERBOSE && echo "  -> Testing if share [opsi_config] already exists"
		set +e
		grep "^\[opsi_config\]" $SAMBA_CONF >/dev/null 2>/dev/null
		status=$?
		set -e
		if [ $status = 0 ]; then
			$VERBOSE && echo "      * share exists"
		else
			$VERBOSE && echo "      * adding share"
			echo "" 				>> $SAMBA_CONF
			echo "[opsi_config]" 			>> $SAMBA_CONF
			echo " available = yes"			>> $SAMBA_CONF
			echo " comment = opsi config share" 	>> $SAMBA_CONF
			echo " path = /var/lib/opsi/config" 	>> $SAMBA_CONF
			echo " writeable = yes" 		>> $SAMBA_CONF
			echo " invalid users = root" 		>> $SAMBA_CONF
		fi
		
		$VERBOSE && echo "  -> Testing if share [opsi_workbench] already exists"
		set +e
		grep "^\[opsi_workbench\]" $SAMBA_CONF >/dev/null 2>/dev/null
		status=$?
		set -e
		if [ $status = 0 ]; then
			$VERBOSE && echo "      * share exists"
		else
			$VERBOSE && echo "      * adding share"
			echo "" 				>> $SAMBA_CONF
			echo "[opsi_workbench]" 		>> $SAMBA_CONF
			echo " available = yes"			>> $SAMBA_CONF
			echo " comment = opsi workbench" 	>> $SAMBA_CONF
			echo " path = /home/opsiproducts" 	>> $SAMBA_CONF
			echo " writeable = yes" 		>> $SAMBA_CONF
			echo " invalid users = root" 		>> $SAMBA_CONF
			echo " create mask = 0660"		>> $SAMBA_CONF
			echo " directory mask = 0770"		>> $SAMBA_CONF
		fi
	else
		echo "        * $SAMBA_CONF not found!"
		echo "        * you will have to configure samba manually!"
		echo "        * look in /usr/share/opsi-depotserver for examples."
	fi
fi

if [ "$CONFIGURE_DHCPD" = "true" ]; then
	# dhcp-server
	echo -e "\nConfiguring dhcpd..."
	if [ -f $DHCPD_CONF ]; then
		set +e
		cat $DHCPD_CONF | grep "ldap-server" >/dev/null 2>/dev/null	
		status=$?
		set -e
		if [ $status = 0 ]; then
			$VERBOSE && echo "        * DHCPD configured by LDAP, leaving as is!"
		else
			extension=`date +%F_%R`
			$VERBOSE && echo "        * Saving current dhcpd.conf to dhcpd.conf.$extension"
			cp -p $DHCPD_CONF $DHCPD_CONF.$extension
			$VERBOSE && echo "        * Patching dhcpd.conf"
			cat << EOF | /usr/bin/python
import sys
from OPSI.Backend.DHCPD import *

nextserver = "$IPADDRESS"
filename = "linux/pxelinux.0"
subnet = "$SUBNET"
netmask = "$NETMASK"

config = Config("$DHCPD_CONF")
config._parseConfig()

print ""

if config._globalBlock.getParameters_hash().get('use-host-decl-names', False):
	print "               use-host-decl-names already enabled"
else:
	p = Parameter(
		startLine 	= -1,
		parentBlock 	= config._globalBlock,
		key 		= 'use-host-decl-names',
		value 		= True )
	config._globalBlock.addComponent(p)

subnets = config._globalBlock.getBlocks('subnet', recursive = True)
if not subnets:
	print "                  no subnets found, adding subnet"
	config._globalBlock.addComponent(
		Block( 
			startLine 	= -1,
			parentBlock 	= config._globalBlock,
			type 		= 'subnet',
			settings 	= ['subnet', subnet, 'netmask', netmask] )
	)

for subnet in config._globalBlock.getBlocks('subnet', recursive = True):
	print "\n               Subnet %s/%s found" % (subnet.settings[1], subnet.settings[3])
	groups = subnet.getBlocks('group')
	if not groups:
		print "                  no groups found, adding group"
		subnet.addComponent(
			Block( 
				startLine 	= -1,
				parentBlock 	= subnet,
				type 		= 'group',
				settings 	= ['group'] )
		)
	for group in subnet.getBlocks('group'):
		print "                  configuring group"
		params = group.getParameters_hash(inherit = 'global')
		if params.get('next-server'):
			print "                     next-server already set"
		else:
			group.addComponent(
				Parameter(
					startLine 	= -1,
					parentBlock 	= group,
					key 		= 'next-server',
					value 		= nextserver ) )
			print "                     next-server set to %s" % nextserver
		if params.get('filename'):
			print "                     filename already set"
		else:
			group.addComponent(
				Parameter(
					startLine 	= -1,
					parentBlock 	= group,
					key 		= 'filename',
					value 		= filename ) )
			print "                     filename set to %s" % filename
config.writeConfig()
print ""
EOF

		chown root:pcpatch $DHCPD_CONF
		chmod 664 $DHCPD_CONF
		fi
	else
		echo "        * $DHCPD_CONF not found!"
		echo "        * you will have to configure dhcpd manually!"
		echo "        * look in /usr/share/opsi-depotserver for examples."
	fi
fi

set +e
cat /etc/sudoers | grep "$DHCPD_INIT restart" >/dev/null 2>/dev/null	
status=$?
set -e
if [ $status = 0 ]; then
	rm /tmp/sudoers 2>/dev/null || true
	touch /tmp/sudoers
	chmod 600 /tmp/sudoers
	cat /etc/sudoers > /tmp/sudoers
	cat /tmp/sudoers | grep -v "$DHCPD_INIT restart" > /etc/sudoers
	rm /tmp/sudoers
fi
echo "opsiconfd ALL=NOPASSWD: $DHCPD_INIT restart" >> /etc/sudoers

touch /etc/opsi/pckeys
touch /etc/opsi/passwd

set +e
/usr/bin/opsi-admin -d method getPcpatchPassword $FQDN >/dev/null 2>/dev/null
status=$?
set -e
if [ $status != 0 ]; then
	# No password set
	/usr/bin/opsi-admin -d method createOpsiBase >/dev/null 2>/dev/null
	
	/usr/bin/opsi-admin -d method createServer "$HOSTNAME" "$DOMAIN" > /dev/null
	
	/usr/bin/opsi-admin -d task setPcpatchPassword "$PCPATCH_PASSWORD"
fi

test -e /var/lib/opsi/.ssh && rm -r /var/lib/opsi/.ssh
/usr/bin/opsi-admin -d method getPcpatchRSAPrivateKey >/dev/null 2>/dev/null || true

eval `opsi-admin -ds method getNetworkConfig_hash | grep nextBootServiceURL`
if [ "$nextBootServiceURL" = "" ]; then
	/usr/bin/opsi-admin -d method setNetworkConfig `/usr/bin/opsi-admin -d method getNetworkConfig_hash | sed "s/\"nextBootServiceURL.*/\"nextBootServiceURL\" : \"https:\/\/${IPADDRESS}:4447\", /" | tr -d '\n' | sed "s/^/'/" | sed "s/$/'/"` "$DOMAIN"
fi

chown opsiconfd:pcpatch /etc/opsi/pckeys
chmod 660 /etc/opsi/pckeys
chown opsiconfd:pcpatch /etc/opsi/passwd
chmod 660 /etc/opsi/passwd

if [ "$CONFIGURE_DHCPD" = "true" ]; then
	echo "Restarting dhcp server..."
	$DHCPD_INIT restart >/dev/null 2>/dev/null || true
fi

if [ "$CONFIGURE_SAMBA" = "true" ]; then
	echo "Reloading samba..."
	$SAMBA_INIT reload >/dev/null 2>/dev/null || true
fi

# ===[ preun ]======================================
%preun

# ===[ postun ]=====================================
%postun
smbpasswd -x pcpatch >/dev/null 2>/dev/null || true

# ===[ files ]======================================
%files
# default attributes
%defattr(-,root,root)

# documentation
#%doc LICENSE README RELNOTES doc

# configfiles
%config(noreplace) /var/lib/opsi/config/global.ini
%config(noreplace) /var/lib/opsi/config/templates/pcproto.ini

# directories
%dir /opt/pcbin/install
%dir /opt/pcbin/pcpatch
%dir /opt/pcbin/utils
%dir /home/opsiproducts
%dir /var/log/opsi
%dir /var/lib/opsi/audit
%dir /var/lib/opsi/config/depots
%dir /var/lib/opsi/config/templates
%dir /var/lib/opsi/products
%dir /var/lib/opsi/config/clients

# ===[ changelog ]==================================
%changelog
* Fri Sep 19 2008 - j.schneider@uib.de
- created new package


