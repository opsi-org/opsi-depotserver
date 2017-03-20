#
# spec file for package opsi-server
#
# Copyright (c) 2010-2017 uib GmbH.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#

Name:           opsi-server
Requires:       python-opsi >= 4.1.1.1 opsiconfd >= 4.0.1 tftp-hpa-server opsipxeconfd >= 4.0 opsi-utils >= 4.0 opsi-linux-bootimage >= 20090927 samba sudo wget
Provides:       opsi-depotserver = %{version}-%{release}
Conflicts:      opsi-server-expert
Obsoletes:      opsi-depotserver < 4.1
%if 0%{?suse_version}
BuildRequires:  pwdutils python-opsi
Requires:       pwdutils
%endif
%if 0%{?rhel_version} || 0%{?centos_version}
Requires:       redhat-lsb
%endif
%if 0%{?rhel_version} >= 700 || 0%{?centos_version} >= 700 || 0%{?fedora_version}
Requires:       samba-client
%endif
Url:            http://www.opsi.org
License:        AGPL-3.0+
Group:          Productivity/Networking/Opsi
AutoReqProv:    on
Version:        4.1.1.1
Release:        4
Summary:        opsi depotserver
%define tarname opsi-depotserver
Source:         opsi-depotserver_4.1.1.1-4.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildArch:      noarch

%define toplevel_dir %{name}-%{version}

%package expert
Group: Productivity/Networking/Opsi
Summary: opsi depotserver in expert mode
# Conflicts: opsi-server
Provides: opsi-server = %{version}
Requires: python-opsi >= 4.0.6.1 opsiconfd >= 4.0.1 tftp-hpa-server opsipxeconfd >= 4.0 opsi-utils >= 4.0 opsi-linux-bootimage >= 20090927

# ===[ description ]================================
%description
opsi depotserver

%description expert
opsi depotserver in expert mode requires manual setup but has no dependencies to samba.

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
%if 0%{?suse_version} == 1110  || 0%{?suse_version} == 1315
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
mkdir -p $RPM_BUILD_ROOT/var/log/opsi/userlogin
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
fi

%post expert
echo "No postinstallation for expert package."

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
%if 0%{?suse_version} == 1110  || 0%{?suse_version} == 1315
# SLES 11 & 12
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
%dir /var/log/opsi/userlogin

# ===[ changelog ]==================================
%changelog
