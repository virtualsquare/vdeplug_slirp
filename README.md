# `vdeplug_slirp`

This is the libvdeplug plugin module to join slirp networks.
It is based on the [libvdeslirp](https://github.com/virtualsquare/libvdeslirp) library.

This module of libvdeplug4 can be used in any program supporting VDE like `vde_plug, vdens, kvm, qemu, user-mode-linux`
and `virtualbox`.

## install 	`vdeplug_slirp`

Requirements: [vdeplug4](https://github.com/rd235/vdeplug4) and [libvdeslirp](https://github.com/virtualsquare/libvdeslirp).

`vdeplug_slirp` uses cmake, so the standard procedure to build and install
this vdeplug plugin module is the following:

```sh
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```

## usage examples (tutorial)

### create a vde namespaces connected to the Internet by slirp

```
vdens -R 10.0.2.3 slirp://
```

Inside the namespace the ip address can be defined by hand or using a dhcp client. e.g.:
```
/sbin/udhcpc -i vde0
```

### connect a vxvde network to the Internet using slirp

```
vde_plug vxvde:// slirp://
```

### connect a tap virtual interface to slirp with port forwarding

TCP port 8080 is forwarded to port 80 of 10.0.2.15

```
vde_plug tap://mytap slirp:///tcpfwd=8080:10.0.2.15:80"
```

### connect a kvm machine to the Internet using slirp (both v4 and v6)
```
kvm .... -device e1000,netdev=vde0,mac=52:54:00:00:00:01 -netdev vde,id=vde0,sock="slirp:///addr=10.1.1.2"
```

## Final Remarks

This version obsoletes the [previous implementation](https://github.com/rd235/vdeplug_slirp) based on the deprecated
old [libslirp](https://github.com/rd235/libslirp).

The only feature still unimplemented in this new code is the redirection to a unix port.
We are working to add this missing feature.
