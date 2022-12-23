<!--
.\" Copyright (C) 2019 VirtualSquare. Project Leader: Renzo Davoli
.\"
.\" This is free documentation; you can redistribute it and/or
.\" modify it under the terms of the GNU General Public License,
.\" as published by the Free Software Foundation, either version 2
.\" of the License, or (at your option) any later version.
.\"
.\" The GNU General Public License's references to "object code"
.\" and "executables" are to be interpreted as the output of any
.\" document formatting or typesetting system, including
.\" intermediate and printed output.
.\"
.\" This manual is distributed in the hope that it will be useful,
.\" but WITHOUT ANY WARRANTY; without even the implied warranty of
.\" MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
.\" GNU General Public License for more details.
.\"
.\" You should have received a copy of the GNU General Public
.\" License along with this manual; if not, write to the Free
.\" Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
.\" MA 02110-1301 USA.
.\"
-->
# NAME

`libvdeplug_slirp` -- slirp vdeplug module

# SYNOPSIS
libvdeplug_slirp.so

# DESCRIPTION

This is the libvdeplug module to join TCP-IP networks using the slirp emulator.

This  module of libvdeplug4 can be used in any program supporting vde like
`vde_plug`, `vdens`, `kvm`, `qemu`, `user-mode-linux` and `virtualbox`.

The vde_plug_url syntax of this module is the following:

```
slirp://[/OPTION][/OPTION]
```

# OPTIONS

  `v4` `v6`
: provide IPv4 or IPv6 service *only*. Both family of protocols are enabled 
: if both `v4` and `v6` options are present of if neither of them have been specified.

  `addr`=_IPv4Addr_/_prefix_ or `host`=_IPv4addr_/_prefix_ 
: Set the IPv4 address of slirp (default value 10.0.2.2/24).

  `addr6`=_IPv6Addr_/_prefix_ or `host6`=_IPv6addr_/_prefix_ 
: Set the IPv6 address of slirp (default value fd00::2/64).

  `hostname`=_name_
: define the hostname (default value: slirp)

  `tftp_server_name`=_name_
: define the hostname of the dhcp server

  `tftp_path`=_path_
: define the path of the directory whose contents are available by the tftp service

  `bootfile`=_path_
: define the path of the bootfile (for bootp)

  `dhcp`=_dhcpIPv4addr_
: set the lowest IP address assigned by dhcp

  `vnameserver`=_IPv4Addr_
: set the address of the IPv4 DNS proxy

  `vnameserver6`=_IPv6Addr_
: set the address of the IPv6 DNS proxy

  `vdnssearch`=_list of domains_
: set the default domains for the neame resolution e.g. `vdnssearch=foo.com,bar.org`

  `vdomainname`=_name_
: set the domain name

  `mtu`=_int\_value_
: define the MTU

  `mru`==_int\_value_
: define the MRU

  `disable_host_loopback`
: disable loopback

  `tcpfwd`=[_hostIP_`:`]_hostport_`:`_guestIP_`:`_guestport_`[,`[_hostIP_`:`]_hostport_`:`_guestIP_`:`_guestport_]...]
: forward TCP port(s).

  `udpfwd`=[_hostIP_`:`]_hostport_`:`_guestIP_`:`_guestport_`[,`[_hostIP_`:`]_hostport_`:`_guestIP_`:`_guestport_]...]
: forward UDP port(s).

  `unixfwd`=[_slirpIP_`:`]_slirpport_`:`_path_`[,`[_slirpIP_`:`]_slirpport_`:`_path_...]
: forward TCP port(s) (from the virtual network) to PF_UNIX socket(s) (commonly used to forward
: ports to a X server) *still unsupported by libslirp*.

  `cmdfwd`=[_slirpIP_`:`]_slirpport_`:`_cmd_`[,`[_slirpIP_`:`]_slirpport_`:`_path_...]
: forward TCP port(s) (from the virtual network) to external command(s).

  `verbose`
: print a table of slirp service configuration.

# EXAMPLES

This vde_plug_url enables both IPv4 and IPv6 (using the default configuration)

```
slirp://
```

Like the previous example but it prints the table of the configuration options

```
slirp:///verbose
```

When a program uses the following vde_plug_url:

```
slirp:///tcpfwd=8080:10.0.2.15:80
```

tcp connections to the host computer port 8080 (any interface) are forwarded to 10.0.2.15  port  80

```
slirp:///tcpfwd=8080:10.0.2.15:80/cmdfwd=10.0.2.5:6000:'socat STDIO UNIX:"/tmp/.X11-unix/X0"'
```

like the previous one plus this uses socat to forward all X-windows requests to 10.0.2.5:0 (port 6000)
to the local server of the display `:0`.

# NOTICE
Virtual  Distributed  Ethernet  is not related in any way with www.vde.com ("Verband der Elektrotechnik, Elektronik
und Informationstechnik" i.e. the German "Association for Electrical, Electronic & Information Technologies").

# SEE ALSO
`vde_plug`(1)

# AUTHOR
VirtualSquare. Project leader: Renzo Davoli

	

