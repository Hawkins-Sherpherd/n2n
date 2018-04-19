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

#define N2N_LINUX_SYSTEMCMD_SIZE 128

static void read_mac(char *ifname, n2n_mac_t mac_addr) {
    int _sock, res;
    struct ifreq ifr;
    macstr_t mac_addr_buf;

    memset (&ifr,0,sizeof(struct ifreq));

    _sock = socket(PF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, ifname);
    res = ioctl(_sock,SIOCGIFHWADDR,&ifr);
    if (res < 0) {
        perror ("Get hw addr");
    } else
        memcpy(mac_addr, ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);

    traceEvent(TRACE_NORMAL, "Interface %s has MAC %s",
               ifname,
               macaddr_str(mac_addr_buf, mac_addr ));
    close(_sock);
}

static int set_mac(int fd, const char* dev, const char* device_mac) {
    int rc;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(struct ifreq));
    if (6 != sscanf(device_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &ifr.ifr_hwaddr.sa_data[0],
        &ifr.ifr_hwaddr.sa_data[1],
        &ifr.ifr_hwaddr.sa_data[2],
        &ifr.ifr_hwaddr.sa_data[3],
        &ifr.ifr_hwaddr.sa_data[4],
        &ifr.ifr_hwaddr.sa_data[5]
    )) {
        traceEvent(TRACE_ERROR, "not a valid mac address: %s\n", device_mac);
        return -1;
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    
    if ( 1 == (ifr.ifr_hwaddr.sa_data[0] % 2) ) {
        traceEvent(TRACE_ERROR, "not a valid singlecast mac address: %s (first octet is uneven)\n", device_mac);
        return -1;
    }
    
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    rc = ioctl(fd, SIOCSIFHWADDR, &ifr);
    if (rc < 0) {
        traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), rc);
        return -1;
    }

    return 0;
}

static int set_ipaddress(const tuntap_dev* device, int static_address) {
    int _sock, rc;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(struct ifreq));
    _sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (_sock < 0) {
        traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), _sock);
        return -1;
    }

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
    ifr.ifr_addr.sa_family = AF_INET;
    ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr = device->ip_addr;
   
    rc = ioctl(_sock, SIOCSIFADDR, &ifr);
    if (rc < 0) {
        traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), rc);
        close(_sock);
        return -1;
    }

    if (static_address) {
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
int tuntap_open(tuntap_dev *device, 
                char *dev, /* user-definable interface name, eg. edge0 */
                const char *address_mode, /* static or dhcp */
                char *device_ip, 
                char *device_mask,
                const char * device_mac,
                int mtu) {
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
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    rc = ioctl(device->fd, TUNSETIFF, (void *)&ifr);

    if(rc < 0) {
        traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), rc);
        close(device->fd);
        return -1;
    }

    /* set mac address */
    if (device_mac && device_mac[0] != '\0') {
        set_mac(device->fd, dev, device_mac);
    }

    /* Store the device name for later reuse */
    strncpy(device->dev_name, ifr.ifr_name, MIN(IFNAMSIZ, N2N_IFNAMSIZ) );

    if (0 == inet_pton(AF_INET, device_ip, &device->ip_addr)) {
        traceEvent(TRACE_ERROR, "invalid ipv4 address: %s\n", device_ip);
        close(device->fd);
        return -1;
    }
    if (0 == inet_pton(AF_INET, device_mask, &device->device_mask)) {
        traceEvent(TRACE_ERROR, "invalid netmask: %s\n", device_mask);
        close(device->fd);
        return -1;
    }
    
    device->mtu = mtu;

    read_mac(dev, device->mac_addr);

    if ( set_ipaddress(device, strncmp("dhcp", address_mode, 5) != 0) < 0 ) {
        traceEvent(TRACE_ERROR, "Could not setup up interface %s", dev);
        close(device->fd);
        return -1;
    }

    return(device->fd);
}

int tuntap_read(struct tuntap_dev *tuntap, unsigned char *buf, int len) {
    return(read(tuntap->fd, buf, len));
}

int tuntap_write(struct tuntap_dev *tuntap, unsigned char *buf, int len) {
    return(write(tuntap->fd, buf, len));
}

void tuntap_close(struct tuntap_dev *tuntap) {
    close(tuntap->fd);
}

/* Fill out the ip_addr value from the interface. Called to pick up dynamic
 * address changes. */
void tuntap_get_address(struct tuntap_dev *tuntap)
{
    int _sock, res;
    struct ifreq ifr;
    char buf[16];

    _sock = socket(PF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, tuntap->dev_name);
    res = ioctl(_sock, SIOCGIFADDR, &ifr);
    if (res < 0) {
        perror ("Get ip addr");
    } else
        tuntap->ip_addr = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;
    close(_sock);

    traceEvent(TRACE_NORMAL, "Interface %s has IP %s",
               tuntap->dev_name,
               inet_ntop(AF_INET, &tuntap->ip_addr, buf, 16));
}

#endif /* #ifdef __linux__ */
