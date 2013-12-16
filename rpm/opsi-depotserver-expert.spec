#
# spec file for package opsi-depotserver
#
# Copyright (c) 2011 uib GmbH.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#

Name:           opsi-depotserver-expert
Requires:       python-opsi >= 4.0.4.3 opsiconfd >= 4.0.1 opsi-atftp opsipxeconfd >= 4.0 opsi-utils >= 4.0 opsi-linux-bootimage >= 20090927
Conflicts:      opsi-depotserver
%if 0%{?suse_version}
BuildRequires:  pwdutils python-opsi
%endif
%if 0%{?rhel_version} || 0%{?centos_version}
Requires:       redhat-lsb
%endif
Url:            http://www.opsi.org
License:        GPL v2 or later
Group:          Productivity/Networking/Opsi
AutoReqProv:    on
Version:        4.0.1.3
Release:        1
Summary:        opsi depotserver
%define tarname opsi-depotserver
Source:         opsi-depotserver_4.0.1.3-1.tar.gz
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
install -m 0755 opsi-set-rights $RPM_BUILD_ROOT/usr/bin/opsi-set-rights

# ===[ clean ]======================================
%clean
rm -rf $RPM_BUILD_ROOT


# ===[ pre ]========================================
%pre

# ===[ post ]=======================================
%post

# ===[ preun ]======================================
%preun

# ===[ postun ]=====================================
%postun

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
%dir /opt/pcbin
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
