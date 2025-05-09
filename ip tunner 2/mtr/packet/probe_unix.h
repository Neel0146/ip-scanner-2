/*
    mtr  --  a network diagnostic tool
    Copyright (C) 2016  Matt Kimball

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef PROBE_UNIX_H
#define PROBE_UNIX_H

#ifndef IPPROTO_SCTP
// Needed for Netbsd.
#define IPPROTO_SCTP           132             /* SCTP */
#endif

/*  The range of local port numbers to use for probes  */
#define MIN_PORT 33434
#define MAX_PORT 65535

/*  We need to track the transmission and timeouts on Unix systems  */
struct probe_platform_t {
    /*  The socket for the outgoing connection  (used by TCP probes)  */
    int socket;

    /*  The time at which the probe is considered lost  */
    struct timeval timeout_time;

    /*  The time at which the probe was sent  */
    struct timeval departure_time;
};

/*  We'll use rack sockets to send and receive probes on Unix systems  */
struct net_state_platform_t {
    /*  true if we were successful at opening IPv4 sockets  */
    bool ip4_present;

    /*  true if we were successful at opening IPv6 sockets  */
    bool ip6_present;

    /* true if ipv4 socket is raw socket */
    bool ip4_socket_raw;

    /* true if ipv6 socket is raw socket */
    bool ip6_socket_raw;

    /*  Send socket for ICMPv6 packets  */
    int icmp4_send_socket;

    /*  Send socket for UDPv6 packets  */
    int udp4_send_socket;

    /*  Socket used to receive IPv4 ICMP replies  */
    int ip4_recv_socket;

    /*  Socket used to probe byte order */
    int ip4_tmp_icmp_socket;

    /*  Socket used to tx & rx non-raw IPv4 icmp packets */
    int ip4_txrx_icmp_socket;

    /*  Socket used to send IPv4 udp packets and receive icmp err packets */
    int ip4_txrx_udp_socket;

    /*  Send socket for ICMPv6 packets  */
    int icmp6_send_socket;

    /*  Send socket for UDPv6 packets  */
    int udp6_send_socket;

    /*  Receive socket for IPv6 packets  */
    int ip6_recv_socket;

    /*  Socket used to tx & rx non-raw IPv6 icmp packets */
    int ip6_txrx_icmp_socket;

    /*  Socket used to send IPv6 udp packets and receive icmp err packets */
    int ip6_txrx_udp_socket;

    /*
       true if we should encode the IP header length in host order.
       (as opposed to network order)
     */
    bool ip_length_host_order;

    /*  true if the operating system supports SCTP sockets  */
    bool sctp_support;

    /*  The next port number to use when creating a new probe  */
    int next_sequence;
};

struct net_state_t;
struct probe_t;
struct mpls_label_t;

void set_socket_nonblocking(
    int socket);

void receive_probe(
    struct net_state_t *net_state,
    struct probe_t *probe,
    int icmp_type,
    const struct sockaddr_storage *remote_addr,
    struct timeval *timestamp,
    int mpls_count,
    struct mpls_label_t *mpls);

int gather_probe_sockets(
    const struct net_state_t *net_state,
    fd_set * write_set);

#endif
