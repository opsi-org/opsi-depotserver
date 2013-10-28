#
# spec file for package opsi-depotserver
#
# Copyright (c) 2010 uib GmbH.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#

Name:           opsi-depotserver
Requires:       python-opsi >= 4.0.1 opsiconfd >= 4.0.1 opsi-atftp opsipxeconfd >= 4.0 opsi-utils >= 4.0 opsi-linux-bootimage >= 20090927 samba sudo wget
Conflicts:      opsi-depotserver-expert
%if 0%{?suse_version}
BuildRequires:  pwdutils python-opsi
Requires:       pwdutils
%endif
%if 0%{?rhel_version} || 0%{?centos_version}
Requires:       dhcp redhat-lsb
%endif
Url:            http://www.opsi.org
License:        GPL v2 or later
Group:          Productivity/Networking/Opsi
AutoReqProv:    on
Version:        4.0.2.2
Release:        1
Summary:        opsi depotserver
%define tarname opsi-depotserver
Source:         opsi-depotserver_4.0.2.2-1.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildArch:      noarch

%define toplevel_dir %{name}-%{version}

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
%if 0%{?sles_version}
mkdir -p $RPM_BUILD_ROOT/var/lib/opsi/workbench
%else
mkdir -p $RPM_BUILD_ROOT/home/opsiproducts
%endif
mkdir -p $RPM_BUILD_ROOT/var/lib/opsi/ntfs-images
mkdir -p $RPM_BUILD_ROOT/var/lib/opsi/depot
mkdir -p $RPM_BUILD_ROOT/var/lib/opsi/repository
mkdir -p $RPM_BUILD_ROOT/var/log/opsi/clientconnect
mkdir -p $RPM_BUILD_ROOT/var/log/opsi/bootimage
mkdir -p $RPM_BUILD_ROOT/var/log/opsi/instlog
mkdir -p $RPM_BUILD_ROOT/usr/bin
install -m 0755 opsi-setup $RPM_BUILD_ROOT/usr/bin/opsi-setup
install -m 0755 opsi-set-rights $RPM_BUILD_ROOT/usr/bin/opsi-set-rights

# ===[ clean ]======================================
%clean
rm -rf $RPM_BUILD_ROOT


# ===[ pre ]========================================
%pre
# add system group fileadmins and users pcpatch
fileadmingroup=$(grep "fileadmingroup" /etc/opsi/opsi.conf | cut -d "=" -f 2 | sed 's/\*//g')
if [ -z "$fileadmingroup" ]; then
	fileadmingroup=pcpatch
fi
if [ $fileadmingroup != pcpatch -a -z "$(getent group $fileadmingroup)" ]; then
	echo "  -> Renaming group pcpatch to $fileadmingroup"
	groupmod -n $fileadmingroup pcpatch
else
	if [ -z "$(getent group $fileadmingroup)"  ]; then
		echo "  -> Adding group $fileadmingroup"
		groupadd -g 992 $fileadmingroup
	fi
fi
if [ -z "`getent passwd pcpatch`" ]; then
	echo "  -> Adding user pcpatch"
	useradd -u 992 -g 992 -d /opt/pcbin/pcpatch -s /bin/bash pcpatch
fi
if [ -z "`getent passwd opsiconfd`" ]; then
	echo "  -> Adding user opsiconfd"
	useradd -u 993 -g 992 -d /var/lib/opsi -s /bin/bash opsiconfd
fi

# ===[ post ]=======================================
%post
if [ $1 -eq 1 ]; then
	# Install
	/usr/bin/opsi-setup --init-current-config --auto-configure-dhcpd --auto-configure-samba || true
	/usr/bin/opsi-setup --set-rights || true
else
	# Upgrade
	/usr/bin/opsi-setup --update-from unknown || true
	/usr/bin/opsi-setup --set-rights /etc/opsi || true
	/usr/bin/opsi-setup --set-rights /tftpboot || true
	mysqlstate=$(/usr/bin/ps -ef | grep -e "^mysql" | grep mysqld)
	mysqlbackend=$(grep -e "^backend_" /etc/opsi/backendManager/dispatch.conf | grep mysql)
	if [ "mysqlstate" != "" -a "mysqlbackend" != "" ]; then
		/usr/bin/opsi-setup --update-mysql
	fi
	#/usr/bin/opsi-setup --set-rights /var/lib/opsi || true
fi

# ===[ preun ]======================================
%preun

# ===[ postun ]=====================================
%postun
if [ $1 -eq 0 ]; then
	smbpasswd -x pcpatch >/dev/null 2>/dev/null || true
fi

# ===[ files ]======================================
%files
# default attributes
%defattr(-,root,root)

/usr/bin/opsi-setup
/usr/bin/opsi-set-rights

# directories
%if 0%{?sles_version}
%dir /var/lib/opsi/workbench
%dir /var/lib/opsi/depot
%else
%dir /home/opsiproducts
%endif
%dir /var/lib/opsi
%dir /var/lib/opsi/repository
%dir /var/lib/opsi/ntfs-images
%dir /var/log/opsi
%dir /var/log/opsi/clientconnect
%dir /var/log/opsi/bootimage
%dir /var/log/opsi/instlog

# ===[ changelog ]==================================
%changelog
