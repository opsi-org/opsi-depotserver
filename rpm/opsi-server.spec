#
# spec file for package opsi-server
#
# Copyright (c) 2010-2017 uib GmbH.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#

Name:           opsi-server
Provides:       opsi-depotserver = %{version}-%{release}
Conflicts:      opsi-server-expert
Obsoletes:      opsi-depotserver < 4.1
Url:            http://www.opsi.org
License:        AGPL-3.0+
Group:          Productivity/Networking/Opsi
AutoReqProv:    on
Version:        4.1.1.1
Release:        6
Summary:        opsi depotserver
Source:         opsi-server_4.1.1.1-6.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildArch:      noarch

Requires:       python-opsi >= 4.1.1.11
Requires:       opsiconfd >= 4.1.1
Requires:       opsi-tftpd
Requires:       opsipxeconfd >= 4.1
Requires:       opsi-utils >= 4.1
Requires:       opsi-linux-bootimage >= 20170620
Requires:       samba
Requires:       sudo
Requires:       wget

%if 0%{?suse_version}
Suggests:       mariadb-server
Suggests:       opsi-windows-support
Suggests:       opsi-linux-support
# RHEL / CentOS do not support this keyword.
%endif

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

%define toplevel_dir %{name}-%{version}

%package expert
Group: Productivity/Networking/Opsi
Summary: opsi depotserver in expert mode
# Conflicts: opsi-server
Provides: opsi-server = %{version}
Requires: python-opsi >= 4.1.1.11 opsiconfd >= 4.1.1 opsi-tftpd opsipxeconfd >= 4.1 opsi-utils >= 4.1 opsi-linux-bootimage >= 20170620

# ===[ description ]================================
%description
opsi server

%description expert
opsi server in expert mode requires manual setup but has no dependencies to samba.

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
mkdir -p $RPM_BUILD_ROOT/usr/bin
install -m 0755 opsi-setup $RPM_BUILD_ROOT/usr/bin/opsi-setup
install -m 0755 opsi-set-rights $RPM_BUILD_ROOT/usr/bin/opsi-set-rights

mkdir -p $RPM_BUILD_ROOT/var/lib/opsi/ntfs-images
mkdir -p $RPM_BUILD_ROOT/var/lib/opsi/depot
mkdir -p $RPM_BUILD_ROOT/var/lib/opsi/repository
mkdir -p $RPM_BUILD_ROOT/var/lib/opsi/workbench
mkdir -p $RPM_BUILD_ROOT/var/log/opsi/clientconnect
mkdir -p $RPM_BUILD_ROOT/var/log/opsi/bootimage
mkdir -p $RPM_BUILD_ROOT/var/log/opsi/instlog
mkdir -p $RPM_BUILD_ROOT/var/log/opsi/userlogin

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
/usr/bin/opsi-setup --auto-configure-dhcpd --auto-configure-samba || true
/usr/bin/opsi-setup --set-rights || true

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
%dir /var/lib/opsi
%dir /var/lib/opsi/depot
%dir /var/lib/opsi/ntfs-images
%dir /var/lib/opsi/repository
%dir /var/lib/opsi/workbench
%dir /var/log/opsi
%dir /var/log/opsi/bootimage
%dir /var/log/opsi/clientconnect
%dir /var/log/opsi/instlog
%dir /var/log/opsi/userlogin

# ===[ changelog ]==================================
%changelog
