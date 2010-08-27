#
# spec file for package opsi-depotserver
#
# Copyright (c) 2010 uib GmbH.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#

Name:           opsi-depotserver
Requires:       python-opsi opsiconfd opsipxeconfd opsi-utils opsi-linux-bootimage samba sudo wget
%if 0%{?suse_version}
BuildRequires:  pwdutils
Requires:       pwdutils dhcp-server
%endif
%if 0%{?rhel_version} || 0%{?centos_version}
Requires:       dhcp
%endif
Url:            http://www.opsi.org
License:        GPL v2 or later
Group:          Productivity/Networking/Opsi
AutoReqProv:    on
Version:        3.99.0
Release:        1
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
%if 0%{?sles_version}
mkdir -p $RPM_BUILD_ROOT/var/lib/opsi/workbench
mkdir -p $RPM_BUILD_ROOT/var/lib/opsi/depot
%else
mkdir -p $RPM_BUILD_ROOT/home/opsiproducts
mkdir -p $RPM_BUILD_ROOT/opt/pcbin/install
%endif
mkdir -p $RPM_BUILD_ROOT/var/lib/opsi/repository
mkdir -p $RPM_BUILD_ROOT/var/log/opsi/clientconnect
mkdir -p $RPM_BUILD_ROOT/var/log/opsi/bootimage
mkdir -p $RPM_BUILD_ROOT/var/log/opsi/instlog
mkdir -p $RPM_BUILD_ROOT/usr/bin
install -m 0755 opsi-setup $RPM_BUILD_ROOT/usr/bin/opsi-setup

# ===[ clean ]======================================
%clean
rm -rf $RPM_BUILD_ROOT


# ===[ pre ]========================================
%pre
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

# ===[ post ]=======================================
%post
arguments=""
#arguments="--auto-configure-dhcpd --auto-configure-samba"
if [ $1 -eq 1 ]; then
	# Install
	/usr/bin/opsi-setup --init-current-config $arguments || true
	/usr/bin/opsi-setup --set-rights || true
else
	# Upgrade
	/usr/bin/opsi-setup --set-rights /etc/opsi || true
	/usr/bin/opsi-setup --set-rights /tftpboot || true
	/usr/bin/opsi-setup --set-rights /var/lib/opsi || true
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

# directories
%if 0%{?sles_version}
%dir /var/lib/opsi/workbench
%dir /var/lib/opsi/depot
%else
%dir /home/opsiproducts
%dir /opt/pcbin/install
%endif
%dir /var/lib/opsi
%dir /var/lib/opsi/repository
%dir /var/log/opsi
%dir /var/log/opsi/clientconnect
%dir /var/log/opsi/bootimage
%dir /var/log/opsi/instlog

# ===[ changelog ]==================================
%changelog
