/*
 * VDE - libvdeplug_slirp module
 * Copyright (C) 2019 Renzo Davoli VirtualSquare
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libvdeplug_mod.h>
#include <slirp/libvdeslirp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

static VDECONN *vde_slirp_open(char *sockname, char *descr,int interface_version,
    struct vde_open_args *open_args);
static ssize_t vde_slirp_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_slirp_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_slirp_datafd(VDECONN *conn);
static int vde_slirp_ctlfd(VDECONN *conn);
static int vde_slirp_close(VDECONN *conn);

struct vdeplug_module vdeplug_ops={
  .vde_open_real=vde_slirp_open,
  .vde_recv=vde_slirp_recv,
  .vde_send=vde_slirp_send,
  .vde_datafd=vde_slirp_datafd,
  .vde_ctlfd=vde_slirp_ctlfd,
  .vde_close=vde_slirp_close
};

struct vde_slirp_conn {
  void *handle;
  struct vdeplug_module *module;

  struct vdeslirp *slirp;
};

static void vde_slirp_dofwd(struct vdeslirp *slirp, int is_udp, char *arg) {
	char *toktmp;
	char *fwditem;
  while ((fwditem = strtok_r(arg, ",", &toktmp)) != NULL) {
    char *fldtmp;
    char *haddrstr, *hport, *gaddrstr, *gport;
    struct in_addr host_addr, guest_addr;
    arg = NULL;

    haddrstr = strtok_r(fwditem, ":", &fldtmp);
    hport = strtok_r(NULL, ":", &fldtmp);
    gaddrstr = strtok_r(NULL, ":", &fldtmp);
    gport = strtok_r(NULL, ":", &fldtmp);
    if (gport == NULL) {
      gport = gaddrstr;
      gaddrstr = hport;
      hport = haddrstr;
      haddrstr = "0.0.0.0";
    }
    if (inet_pton(AF_INET, haddrstr, &host_addr) == 1 &&
        inet_pton(AF_INET, gaddrstr, &guest_addr) == 1)
      vdeslirp_add_fwd(slirp, is_udp,
          host_addr, atoi(hport),
          guest_addr, atoi(gport));
  }
}

static void vde_slirp_dounixfwd(struct vdeslirp *slirp, char *arg) {
	char *toktmp;
	char *fwditem;
	while ((fwditem = strtok_r(arg, ",", &toktmp)) != NULL) {
		char *fldtmp;
		char *haddrstr, *hport, *path;
		struct in_addr host_addr;
		arg = NULL;

		haddrstr = strtok_r(fwditem, ":", &fldtmp);
		hport = strtok_r(NULL, ":", &fldtmp);
		path = strtok_r(NULL, ":", &fldtmp);
		if (path == NULL) {
			path = hport;
			hport = haddrstr;
			haddrstr = "0.0.0.0";
		}
		if (inet_pton(AF_INET, haddrstr, &host_addr) == 1 &&
				path != 0)
			vdeslirp_add_unixfwd(slirp, host_addr, atoi(hport), path);
	}
}

static const char **vdnssearch_copy(char *list) {
  const char **retval = NULL;
  int i, count;
  if (list == NULL)
    return NULL;
  for (i = 0, count = 2; list[i] != 0; i++)
    count += (list[i] == ',');
  retval = malloc(count * sizeof(char *));
  if (retval != NULL) {
    const char **scan = retval;;
    char *toktmp, *item;
    for (; (item = strtok_r(list, ",", &toktmp)) != NULL; list = NULL)
      *scan++ = strdup(item);
    *scan = NULL;
  }
  return retval;
}

static void vdnssearch_free(const char **argv) {
	const char **scan;
	for (scan = argv; *scan; scan++)
		free((void *) *scan);
	free(argv);
}

#define NTOP_BUFSIZE 128
static void verbose_configuration(struct SlirpConfig *cfg) {
	char buf[NTOP_BUFSIZE];
	fprintf(stderr, "SLIRP configuration\n");
	fprintf(stderr, "version       %d\n", cfg->version);
	fprintf(stderr, "ipv4-enable   %d\n", cfg->in_enabled);
	fprintf(stderr, "ipv4-network  %s\n", inet_ntop(AF_INET, &cfg->vnetwork, buf, NTOP_BUFSIZE));
	fprintf(stderr, "ipv4-netmask  %s\n", inet_ntop(AF_INET, &cfg->vnetmask, buf, NTOP_BUFSIZE));
	fprintf(stderr, "ipv4-host     %s\n", inet_ntop(AF_INET, &cfg->vhost, buf, NTOP_BUFSIZE));
	fprintf(stderr, "ipv6-enabled  %d\n", cfg->in6_enabled);
	fprintf(stderr, "ipv6-prefix   %s\n", inet_ntop(AF_INET6, &cfg->vprefix_addr6, buf, NTOP_BUFSIZE));
	fprintf(stderr, "ipv6-preflen  %d\n", cfg->vprefix_len);
	fprintf(stderr, "ipv6-host     %s\n", inet_ntop(AF_INET6, &cfg->vhost6, buf, NTOP_BUFSIZE));
	fprintf(stderr, "hostname      %s\n", cfg->vhostname);
	fprintf(stderr, "tftp-servname %s\n", cfg->tftp_server_name);
	fprintf(stderr, "tftp-path     %s\n", cfg->tftp_path);
	fprintf(stderr, "bootfile      %s\n", cfg->bootfile);
	fprintf(stderr, "dhcp-start    %s\n", inet_ntop(AF_INET, &cfg->vdhcp_start, buf, NTOP_BUFSIZE));
	fprintf(stderr, "ipv4-vDNS     %s\n", inet_ntop(AF_INET, &cfg->vnameserver, buf, NTOP_BUFSIZE));
	fprintf(stderr, "ipv6-vDNS     %s\n", inet_ntop(AF_INET6, &cfg->vnameserver6, buf, NTOP_BUFSIZE));
	fprintf(stderr, "vDNS-search   ");
	if (cfg->vdnssearch) {
		const char **scan;
		for (scan = cfg->vdnssearch; *scan; scan++)
			fprintf(stderr, "%s ", *scan);
	}
	fprintf(stderr, "\n");
	fprintf(stderr, "vdomainname   %s\n", cfg->vdomainname);
	fprintf(stderr, "MTU(0=def)    %d\n", cfg->if_mtu);
	fprintf(stderr, "MTU(0=def)    %d\n", cfg->if_mru);
	fprintf(stderr, "disable-lback %d\n", cfg->disable_host_loopback);
	fprintf(stderr, "enable-emu    %d\n", cfg->enable_emu);
}

static VDECONN *vde_slirp_open(char *sockname, char *descr,int interface_version,
		struct vde_open_args *open_args) {
	struct SlirpConfig cfg;
	struct vde_slirp_conn *newconn = NULL;
	char *restricted = NULL;
	char *v4str = NULL;
	char *v6str = NULL;
	char *host4 = NULL;
	char *host6 = NULL;
	char *vhostname = NULL;
	char *tftp_server_name = NULL;
	char *tftp_path = NULL;
	char *bootfile = NULL;
	char *dhcp = NULL;
	char *vnameserver = NULL;
	char *vnameserver6 = NULL;
	char *vdnssearch = NULL;
	char *vdomainname = NULL;
	char *mtu = NULL;
	char *mru = NULL;
	char *disable_host_loopback = NULL;
	char *tcpfwd = NULL;
	char *udpfwd = NULL;
	char *unixfwd = NULL;
	char *verbose = NULL;
	struct addrinfo hints;
	struct addrinfo *result;
	struct vdeparms parms[] = {
		{"restricted", &restricted},
		{"v4", &v4str},
		{"v6", &v6str},
		{"addr", &host4},
		{"addr6", &host6},
		{"hostname", &vhostname},
		{"tftp_server_name", &tftp_server_name},
		{"tftp_path", &tftp_path},
		{"bootfile", &bootfile},
		{"dhcp", &dhcp},
		{"vnameserver", &vnameserver},
		{"vnameserver6", &vnameserver6},
		{"vdnssearch", &vdnssearch},
		{"vdomainname", &vdomainname},
		{"mtu", &mtu},
		{"mru", &mru},
		{"disable_host_loopback", &disable_host_loopback},
		{"tcpfwd", &tcpfwd},
		{"udpfwd", &udpfwd},
		{"unixfwd", &unixfwd},
		{"verbose", &verbose},
		{NULL, NULL}};
	memset(&hints, 0, sizeof(struct addrinfo));
	if (vde_parseparms(sockname, parms) != 0)
		return NULL;

	vdeslirp_init(&cfg, VDE_INIT_DEFAULT);
	if (restricted) cfg.restricted = 1;
	if (v4str && !v6str) cfg.in6_enabled = 0;
	if (v6str && !v4str) cfg.in_enabled = 0;
	if (host4) {
		int prefix = 24;
		char *slash = strchr(host4, '/');
		if (slash) {
			prefix = atoi(slash+1);
			*slash = 0;
		}
		inet_pton(AF_INET, host4, &(cfg.vhost));
		vdeslirp_setvprefix(&cfg, prefix);
	}
	if (host6) {
		int prefix = 64;
		char *slash = strchr(host6, '/');
		if (slash) {
			prefix = atoi(slash+1);
			*slash = 0;
		}
		inet_pton(AF_INET6, host6, &(cfg.vhost6));
		vdeslirp_setvprefix6(&cfg, prefix);
	}
	if (vhostname) cfg.vhostname = vhostname;
	if (tftp_server_name) cfg.tftp_server_name = tftp_server_name;
	if (tftp_path) cfg.tftp_path = tftp_path;
	if (bootfile) cfg.bootfile = bootfile;
	if (dhcp) inet_pton(AF_INET, dhcp, &(cfg.vdhcp_start));
	if (vnameserver) inet_pton(AF_INET, vnameserver, &(cfg.vnameserver));
	if (vnameserver6) inet_pton(AF_INET6, vnameserver6, &(cfg.vnameserver6));
	if (vdnssearch) cfg.vdnssearch = vdnssearch_copy(vdnssearch);
	if (vdomainname) cfg.vdomainname = vdomainname;
	if (mtu) cfg.if_mtu = atoi(mtu);
	if (mru) cfg.if_mru = atoi(mru);
	if (disable_host_loopback) cfg.disable_host_loopback = 1;
	if (verbose) verbose_configuration(&cfg);

	struct vdeslirp *slirp = vdeslirp_open(&cfg);

	if (slirp != NULL) {
		struct vde_slirp_conn *newconn = calloc(1, sizeof(*newconn));
		if (newconn == NULL) {
			errno = ENOMEM;
			vdeslirp_close(slirp);
		} else {
			if (tcpfwd)
				vde_slirp_dofwd(slirp, 0, tcpfwd);
			if (udpfwd)
				vde_slirp_dofwd(slirp, 1, udpfwd);
			if (unixfwd)
				vde_slirp_dounixfwd(slirp, unixfwd);
			if (cfg.vdnssearch != NULL) 
				vdnssearch_free(cfg.vdnssearch);
			newconn->slirp = slirp;
			return (VDECONN *) newconn;
		}
	}
	return NULL;
}

static ssize_t vde_slirp_recv(VDECONN *conn,void *buf,size_t len,int flags) {
	struct vde_slirp_conn *vde_conn = (struct vde_slirp_conn *)conn;
	return vdeslirp_recv(vde_conn->slirp, buf, len);
}

static ssize_t vde_slirp_send(VDECONN *conn,const void *buf,size_t len,int flags) {
	struct vde_slirp_conn *vde_conn = (struct vde_slirp_conn *)conn;
	return vdeslirp_send(vde_conn->slirp, buf, len);
}

static int vde_slirp_datafd(VDECONN *conn) {
	struct vde_slirp_conn *vde_conn = (struct vde_slirp_conn *)conn;
	return vdeslirp_fd(vde_conn->slirp);
}

static int vde_slirp_ctlfd(VDECONN *conn) {
	return -1;
}

static int vde_slirp_close(VDECONN *conn) {
	struct vde_slirp_conn *vde_conn = (struct vde_slirp_conn *)conn;
	int rval = vdeslirp_close(vde_conn->slirp);
	if (rval == 0)
		free(vde_conn);
	return 0;
}

