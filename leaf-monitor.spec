%define _build_id_links none
%define debug_package %{nil}

Summary:          Leaf Server Console
License:          LGPL
Name:             leaf-monitor
Version:          1.3
Release:          1%{?dist}

URL:              http://www.icapsql.com/
Source0:          %{name}-%{version}.tar.gz

Requires:         c-icap-libs c-icap mariadb c-icap-leaf
BuildRequires:    systemd
BuildRequires:    gdbm-devel openldap-devel perl-devel c-icap-devel
BuildRequires:    mariadb-devel 

%description 
The %{name} package contains the Leaf Server Console Monitor Program.

%prep
%setup -q -n %{name}-%{version}

%build
%{__make} 

%install
[ -n "%{buildroot}" -a "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}
%{__mkdir_p} %{buildroot}%{_sbindir}
%{__mkdir_p} %{buildroot}%{_bindir}
%{__make} \
	DESTDIR=%{buildroot} BINDIR=%{_bindir} \
	install

%pre

%post

%preun

%postun

%files
%defattr(-,root,root)
%{_bindir}/leafmon

%changelog
