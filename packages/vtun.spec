# By default, builds without socks-support.
# To build with socks-support, issue:
#   rpm --define "USE_SOCKS yes" ...

# By default, builds with LZO support (available for any RPM system)
# To disable LZO, issue:
#   rpm --define "NO_USE_LZO yes" ...

# define variables here for older RPM versions.
%define name	vtun
%define version	2.9.91
%define release	1

# expansion of the previous part.
# get the distro mark (eg rh70)
%define	_dis	%(case `rpm -qf /etc/issue 2>/dev/null` in (redhat-*) echo rh;; (mandrake-*) echo mdk ;; (fedora-*) echo fc ;; (openlinux-*) echo ol ;; (whitebox-*) echo wb ;; (SuSE-*) echo suse ;; esac)
%define _tro	%(rpm -qf --qf "%%{version}" /etc/issue | sed 's/\\.//g' )

%define	rc_dir_suse	/etc/init.d
%define	lock_dir_suse	/var/lock/subsys/vtunnel
%define	log_dir_suse	/var/log/vtunnel

# now apply the components
# If anyone can find system that strangers understand, that still
# enables one SRPM to build for 17 distros, I'm open to suggestions.
%define	_requires	%{expand:%%{?_requires_%{_dis}%{_tro}:%%_requires_%{_dis}%{_tro}}%%{!?_requires_%{_dis}%{_tro}:%%{?_requires_%{_dis}:%%_requires_%{_dis}}%%{!?_requires_%{_dis}:%{_requires}}}}
%define	rc_dir	%{expand:%%{?rc_dir_%{_dis}%{_tro}:%%rc_dir_%{_dis}%{_tro}}%%{!?rc_dir_%{_dis}%{_tro}:%%{?rc_dir_%{_dis}:%%rc_dir_%{_dis}}%%{!?rc_dir_%{_dis}:/etc/rc.d/init.d}}}
%define	lock_dir	%{expand:%%{?lock_dir_%{_dis}%{_tro}:%%lock_dir_%{_dis}%{_tro}}%%{!?lock_dir_%{_dis}%{_tro}:%%{?lock_dir_%{_dis}:%%lock_dir_%{_dis}}%%{!?lock_dir_%{_dis}:/var/lock/vtund}}}
%define	log_dir	%{expand:%%{?log_dir_%{_dis}%{_tro}:%%log_dir_%{_dis}%{_tro}}%%{!?log_dir_%{_dis}%{_tro}:%%{?log_dir_%{_dis}:%%log_dir_%{_dis}}%%{!?log_dir_%{_dis}:/var/log/vtund}}}

Name: 		%{name}
Version: 	%{version}
Release: 	%{release}
Copyright: 	GPL
Group: 		System Environment/Daemons
Url: 		http://vtun.sourceforge.net/
Source: 	http://vtun.sourceforge.net/%{name}-%{version}.tar.gz
Summary: 	Virtual tunnel over TCP/IP networks.
Summary(pl):	Wirtualne tunele poprzez sieci TCP/IP
Vendor: 	Maxim Krasnyansky <max_mk@yahoo.com>
Packager: 	Bishop Clark (LC957) <bishop@platypus.bc.ca>
BuildRoot: 	%{?_tmppath:%{_tmppath}}%{!?_tmppath:%{tmpdir}}/%{name}-%{version}-root-%(id -u -n)
Obsoletes: 	vppp
BuildRequires:  autoconf
BuildRequires:  automake

BuildRequires: 	bison
BuildRequires: 	flex
BuildRequires: 	autoconf
BuildRequires: 	automake

# please check the FAQ for this question, and mail Bishop if there is
# no FAQ entry.
%define	_requires	tun libz-devel %{!?_without_ssl:openssl-devel} %{!?NO_USE_LZO: lzo-devel}

# Caldera has funny zlib
%define	_requires_ol	tun libz-devel %{!?_without_ssl:openssl-devel} %{!?NO_USE_LZO:lzo-devel}
# Mandrake has unpredictable devel package names
%define	_requires_mdk	tun zlib1-devel %{!?_without_ssl:libopenssl0-devel} %{!?NO_USE_LZO: liblzo1-devel}

# normally, NOT depending on the tun package encourages other apps to
# clobber the modules.conf file. In this case, the reverse is true,
# since FCx actually includes all the necessary entries.  So no tun.
%define	_requires_fc	libz-devel %{!?_without_ssl:openssl-devel} %{!?NO_USE_LZO: lzo-devel}

Requires:	%{_requires}

%description
VTun provides a method for creating Virtual Tunnels over TCP/IP
networks and allows one to shape, compress, encrypt traffic in those
tunnels.  Supported types of tunnels are: PPP, IP, Ethernet and most
other serial protocols and programs.

VTun is easily and highly configurable: it can be used for various
network tasks like VPN, Mobile IP, Shaped Internet access, IP address
saving, etc.  It is completely a user space implementation and does
not require modification to any kernel parts.

This package is built with%{!?USE_SOCKS:out} SOCKS-support.
%{?NO_USE_LZO:This package is built without LZO support.}

%description -l pl
VTun umo¿liwia tworzenie Wirtualnych Tunelu poprzez sieci TCP/IP wraz
z przydzielaniem pasma, kompresj±, szyfrowaniem danych w tunelach.
Wspierane typy tuneli to: PPP, IP, Ethernet i wiêkszo¶æ pozosta³ych
protoko³ów szeregowych.


%prep

%setup -n %{name}
%{__aclocal}
%{__autoconf}
%configure				   \
            --prefix=%{_exec_prefix} 	   \
	    --sysconfdir=/etc 		   \
	    --localstatedir=%{_var}	   \
%{?NO_USE_LZO: --disable-lzo} \
%{?USE_SOCKS: --enable-socks}

%build
%if "%_dis" == "suse"
%{__make} LOCK_DIR=%{lock_dir} STAT_DIR=/var/log/vtunnel
%else
%{__make}
%endif

%install
[ $RPM_BUILD_ROOT != / ] && rm -rf $RPM_BUILD_ROOT
%__install -d $RPM_BUILD_ROOT%{rc_dir}

%if "%_dis" == "suse"
install scripts/vtund.rc.suse $RPM_BUILD_ROOT%{rc_dir}/vtund
%else 
install scripts/vtund.rc.red_hat $RPM_BUILD_ROOT%{rc_dir}/vtund
%endif

make install SBIN_DIR=$RPM_BUILD_ROOT%{_sbindir} \
        MAN_DIR=$RPM_BUILD_ROOT%{_mandir} \
        ETC_DIR=$RPM_BUILD_ROOT/etc \
        VAR_DIR=$RPM_BUILD_ROOT%{_var} \
        LOCK_DIR=$RPM_BUILD_ROOT%{lock_dir} \
	INSTALL_OWNER=

%__install -d $RPM_BUILD_ROOT/etc/xinetd.d
%__sed 's:/usr/local:%{_prefix}:' scripts/vtund.xinetd \
	> $RPM_BUILD_ROOT/etc/xinetd.d/vtun

%if "%_dis" == "suse"
# SuSE RC.CONFIG templates
install -d $RPM_BUILD_ROOT/var/adm/fillup-templates
install -m 644 scripts/vtund.rc.suse.config $RPM_BUILD_ROOT/var/adm/fillup-templates/rc.config.vtund

# rcvtund
ln -sf ../..%{rc_dir}/vtund $RPM_BUILD_ROOT/usr/sbin/rcvtund

%endif

%post
%if "%_dis" == "suse"
#rc config
echo "Updating etc/rc.config..."
if [ -x bin/fillup ] ; then
  bin/fillup -q -d = etc/rc.config var/adm/fillup-templates/rc.config.vtund
else
  echo "ERROR: fillup not found. This should not happen. Please compare"
  echo "etc/rc.config and var/adm/fillup-templates/rc.config.vtund and"
  echo "update by hand."
fi
sbin/insserv etc/init.d/vtund
%endif

%clean
[ $RPM_BUILD_ROOT != / ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(644,root,root)
%doc ChangeLog Credits FAQ README README.Setup README.Shaper TODO
%doc TODO vtund.conf 
%attr(755,root,root) %config %{rc_dir}/vtund
%attr(600,root,root) %config(noreplace) /etc/vtund.conf
%attr(755,root,root) %{_sbindir}/vtund
%attr(755,root,root) %dir %{log_dir}
%attr(755,root,root) %dir %{lock_dir}
%{_mandir}/man8/vtund.8*
#%{_mandir}/man8/vtun.8*
%{_mandir}/man5/vtund.conf.5*
/etc/xinetd.d/vtun
%if "%_dis" == "suse"
%attr(755,root,root) %{_sbindir}/rcvtund
/var/adm/fillup-templates/rc.config.vtund
%endif

%changelog
* Fri Aug 27 2004 Bishop Clark (LC957) <bishop@platypus.bc.ca> 2.9.91-1
- xinetd prototype file
- Nickolai 'kolya' Zeldovich's mlockall() patch
- Added upper time bound to packet-based resync to reduce resync delay

* Tue Aug  3 2004 Bishop Clark (LC957) <bishop@platypus.bc.ca> 2.9.90-2
- incorporation of some of PLD fixes
- move to more macros and less if/thens
- one ugly SPEC for 18 happy distros.

* Sun Mar 14 2004 Bishop Clark (LC957) <bishop@platypus.bc.ca> 2.9.90-1
- new 3.0.0 pre-release.  
- better ciphers and a persist-keep bugfix.
* Sun Mar 23 2003 Bishop Clark (LC957) <bishop@platypus.bc.ca> 2.6-1.1
- alter packaging to accomodate MDKs non-standard devel pkg names

* Tue Mar 18 2003 Bishop Clark (LC957) <bishop@platypus.bc.ca> 2.6-1
- new release

* Sat Aug 17 2002 Bishop Clark (LC957) <bishop@platypus.bc.ca> 2.5-5
- fix GROUP for amanda's genhdlist and Michael Van Donselaar

* Tue Jun 5 2002 Bishop Clark (LC957) <bishop@platypus.bc.ca> 2.5-4
- Deprecated redundant directory creation in install
- More undisputed patches by Willems Luc for SuSE support
- Update of one SuSE config file, addition of another as per 
  Willems Luc

* Mon Jan 21 2002 Bishop Clark (LC957) <bishop@platypus.bc.ca> 2.5-3
- Macros updating as per 2.5 for better cross-distro build
- Added NO_USE_LZO compile option as per Willems Luc
- very initial SuSE 7.3 support as per Willems Luc
- removed packaging of vtun->vtund symlink in man8 as per build
  behaviour
- re-edited as per Jan 14 2002 edits

* Mon Jan 14 2002 Bishop Clark (LC957) <bishop@platypus.bc.ca> 2.5-2
- noreplace to vtund.conf to prevent Freshen from clobbering config.
- added buildrequires to prevent failed builds.

* Mon May 29 2000 Michael Tokarev <mjt@tls.msk.ru>
- Allow to build as non-root (using new INSTALL_OWNER option)
- Added vtund.conf.5 manpage
- Allow compressed manpages
- Added cleanup of old $RPM_BUILD_ROOT at beginning of %%install stage

* Sat Mar 04 2000 Dag Wieers <dag@mind.be> 
- Added USE_SOCKS compile option.
- Added Prefix-header

* Sat Jan 29 2000 Dag Wieers <dag@mind.be> 
- Replaced SSLeay-dependency by openssl-dependency
- Replaced README.Config by README.Setup
- Added TODO

* Tue Nov 23 1999 Dag Wieers <dag@mind.be> 
- Added Url and Obsoletes-headers
- Added ChangeLog ;)
- Changed summary
