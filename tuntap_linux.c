/*
 * (C) 2007-09 - Luca Deri <deri@ntop.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>
*/

#include "n2n.h"

#ifdef __linux__
#include <net/if_arp.h>

struct in6_ifreq {
    struct in6_addr ifr6_addr;
    uint32_t ifr6_prefixlen;
    unsigned int ifr6_ifindex;
};

static void read_mac(const char *ifname, n2n_mac_t mac_addr) {
    int _sock, res;
    struct ifreq ifr;
    macstr_t mac_addr_buf;

    memset(&ifr, 0, sizeof(struct ifreq));

    _sock = socket(PF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, ifname, N2N_IFNAMSIZ);

    res = ioctl(_sock, SIOCGIFHWADDR, &ifr);
    if (res < 0) {
        traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), res);
    } else
        memcpy(mac_addr, &ifr.ifr_ifru.ifru_hwaddr.sa_data, sizeof(n2n_mac_t));

    traceEvent(TRACE_NORMAL, "Interface %s has MAC %s",
               ifname,
               macaddr_str(mac_addr_buf, mac_addr));
    close(_sock);
}

static int set_mac(int fd, const char* dev, n2n_mac_t device_mac) {
    int rc;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(struct ifreq));
    memcpy(&ifr.ifr_hwaddr.sa_data, device_mac, sizeof(n2n_mac_t));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    rc = ioctl(fd, SIOCSIFHWADDR, &ifr);
    if (rc < 0) {
        traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), rc);
        return -1;
    }
    return 0;
}

static int set_ipaddress(const tuntap_dev* device, int static_address) {
    int _sock, _sock_in6, rc;
    struct ifreq ifr;
    struct in6_ifreq ifr6;

   
    _sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (_sock < 0) {
        traceEvent(TRACE_ERROR, "socket() [%s][%d]\n", strerror(errno), _sock);
        return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, device->dev_name, IFNAMSIZ);

    /* set MTU */
    ifr.ifr_mtu = device->mtu;
    rc = ioctl(_sock, SIOCSIFMTU, &ifr);
    if (rc < 0) {
        traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), rc);
        close(_sock);
        return -1;
    }

    /* set ipv4 address */
    if (static_address) {
        memset(&ifr, 0, sizeof(struct ifreq));
        strncpy(ifr.ifr_name, device->dev_name, IFNAMSIZ);

        ifr.ifr_addr.sa_family = AF_INET;
        ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr = device->ip_addr;
   
        rc = ioctl(_sock, SIOCSIFADDR, &ifr);
        if (rc < 0) {
            traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), rc);
            close(_sock);
            return -1;
        }

        /* set netmask */
        ifr.ifr_addr.sa_family = AF_INET;
        ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr = device->device_mask;

        rc = ioctl(_sock, SIOCSIFNETMASK, &ifr);
        if (rc < 0) {
            traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), rc);
            close(_sock);
            return -1;
        }

    }

    /* set ipv6 address */
    if (static_address && device->ip6_prefixlen > 0) {
        _sock_in6 = socket(PF_INET6, SOCK_DGRAM, IPPROTO_IP);

        /* get the interface number */
        memset(&ifr, 0, sizeof(struct ifreq));
        strncpy(ifr.ifr_name, device->dev_name, IFNAMSIZ);
        rc = ioctl(_sock_in6, SIOGIFINDEX, &ifr);
        if (rc < 0) {
            traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), rc);
            close(_sock_in6);
            close(_sock);
            return -1;
        }
   
        /* set address and prefix */
        memset(&ifr6, 0, sizeof(ifr6));
        struct in6_addr* in6_addr = (struct in6_addr*) &ifr6.ifr6_addr;
        memcpy(in6_addr, &device->ip6_addr, IPV6_SIZE);
        ifr6.ifr6_prefixlen = device->ip6_prefixlen;
        ifr6.ifr6_ifindex = ifr.ifr_ifindex;
        rc = ioctl(_sock_in6, SIOCSIFADDR, &ifr6);
        if (rc < 0) {
            traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), rc);
            close(_sock_in6);
            close(_sock);
            return -1;
        }

        close(_sock_in6);
    }
    
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, device->dev_name, IFNAMSIZ);

    /* retrieve flags */
    rc = ioctl(_sock, SIOCGIFFLAGS, &ifr);
    if (rc < 0) {
        traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), rc);
        close(_sock);
        return -1;
    }

    /* bring up interface */
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    rc = ioctl(_sock, SIOCSIFFLAGS, &ifr);
    if (rc < 0) {
        traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), rc);
        close(_sock);
        return -1;
    }
    
    close(_sock);
    return 0;
}

/* ********************************** */

/** @brief  Open and configure the TAP device for packet read/write.
 *
 *  This routine creates the interface via the tuntap driver then uses ifconfig
 *  to configure address/mask and MTU.
 *
 *  @param device      - [inout] a device info holder object
 *  @param dev         - user-defined name for the new iface, 
 *                       if NULL system will assign a name
 *  @param device_ip   - address of iface
 *  @param device_mask - netmask for device_ip
 *  @param mtu         - MTU for device_ip
 *
 *  @return - negative value on error
 *          - non-negative file-descriptor on success
 */
int tuntap_open(tuntap_dev *device, struct tuntap_config* config) {
    char *tuntap_device = "/dev/net/tun";
    struct ifreq ifr;
    int rc;

    device->fd = open(tuntap_device, O_RDWR | O_CLOEXEC);
    if(device->fd < 0) {
        printf("ERROR: ioctl() [%s][%d]\n", strerror(errno), errno);
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP|IFF_NO_PI; /* Want a TAP device for layer 2 frames. */
    strncpy(ifr.ifr_name, config->if_name, IFNAMSIZ);
    rc = ioctl(device->fd, TUNSETIFF, (void *)&ifr);

    if(rc < 0) {
        traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), rc);
        close(device->fd);
        return -1;
    }

    /* set mac address */
    if (!(config->device_mac[0] == 0 && config->device_mac[1] == 0 &&
          config->device_mac[2] == 0 && config->device_mac[3] == 0 &&
          config->device_mac[4] == 0 && config->device_mac[5] == 0))
    {
        set_mac(device->fd, config->if_name, config->device_mac);
    }

    /* Store the device name for later reuse */
    strncpy(device->dev_name, config->if_name, MIN(IFNAMSIZ, N2N_IFNAMSIZ) );

    memcpy(&device->ip_addr, &config->ip_addr, sizeof(config->ip_addr));
    memcpy(&device->device_mask, &config->netmask, sizeof(config->netmask));
    memcpy(&device->ip6_addr, &config->ip6_addr, sizeof(config->ip6_addr));

    device->ip6_prefixlen = config->ip6_prefixlen;
    device->mtu = config->mtu;

    read_mac(device->dev_name, device->mac_addr);

    if ( set_ipaddress(device, !config->dyn_ip4) < 0 ) {
        traceEvent(TRACE_ERROR, "Could not setup up interface %s", device->dev_name);
        close(device->fd);
        return -1;
    }

    return(device->fd);
}

ssize_t tuntap_read(struct tuntap_dev *tuntap, unsigned char *buf, size_t len) {
    return(read(tuntap->fd, buf, len));
}

ssize_t tuntap_write(struct tuntap_dev *tuntap, unsigned char *buf, size_t len) {
    return(write(tuntap->fd, buf, len));
}

void tuntap_close(struct tuntap_dev *tuntap) {
    close(tuntap->fd);
}

/* Fill out the ip_addr value from the interface. Called to pick up dynamic
 * address changes. */
void tuntap_get_address(struct tuntap_dev *tuntap) {
    int _sock, res;
    struct ifreq ifr;
    ipstr_t buf;

    memset(&ifr, 0, sizeof(ifr));
    _sock = socket(PF_INET, SOCK_DGRAM, 0);

    strcpy(ifr.ifr_name, tuntap->dev_name);
    ifr.ifr_addr.sa_family = AF_INET;
    
    res = ioctl(_sock, SIOCGIFADDR, &ifr);
    if (res < 0) {
        perror ("Get ip addr");
    } else
        tuntap->ip_addr = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;
    close(_sock);

    traceEvent(TRACE_NORMAL, "Interface %s has IPv4 %s",
               tuntap->dev_name,
               inet_ntop(AF_INET, &tuntap->ip_addr, buf, sizeof(buf)));
}

#endif /* #ifdef __linux__ */
