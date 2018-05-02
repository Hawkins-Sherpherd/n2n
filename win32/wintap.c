/*
  (C) 2007-09 - Luca Deri <deri@ntop.org>
*/

#include "../n2n.h"
#include "n2n_win32.h"

/* 1500 bytes payload + 14 bytes ethernet header + 4 bytes VLAN tag */
#define MTU 1518

static void print_windows_message(DWORD rc) {
    LPVOID lpMsgBuf;
    if (FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM | 
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        rc,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
        (LPTSTR) &lpMsgBuf,
        0,
        NULL ))
    {
        printf("Error: %ls", (WCHAR*) lpMsgBuf);
    }
    LocalFree( lpMsgBuf );
}

void initWin32() {
    WSADATA wsaData;
    int err;

    err = WSAStartup(MAKEWORD(2, 2), &wsaData );
    if( err != 0 ) {
        /* Tell the user that we could not find a usable */
        /* WinSock DLL.                                  */
        printf("FATAL ERROR: unable to initialise Winsock 2.x.");
        exit(-1);
    }
}

static ULONG get_adapter_index(PWSTR device_name) {
    CLSID guid;
    NET_LUID luid;
    NET_IFINDEX index = NET_IFINDEX_UNSPECIFIED;

    if (CLSIDFromString(device_name, &guid) != NO_ERROR)
        return NET_IFINDEX_UNSPECIFIED;
    
    if (ConvertInterfaceGuidToLuid(&guid, &luid) != NO_ERROR)
        return NET_IFINDEX_UNSPECIFIED;
    
    if (ConvertInterfaceLuidToIndex(&luid, &index) != NO_ERROR)
        return NET_IFINDEX_UNSPECIFIED;

    return index;
}

static DWORD set_dhcp(struct tuntap_dev* device) {
    IP_ADAPTER_INDEX_MAP iface;
    DWORD rc;

    iface.Index = device->ifIdx;
    _snwprintf(iface.Name, MAX_ADAPTER_NAME, L"\\DEVICE\\TCPIP_%s", device->device_name);
    rc = IpReleaseAddress(&iface);
    //printf("rc=%u\n",rc);
    rc = IpRenewAddress(&iface);
    //printf("rc=%u\n",rc);
    
    // print_windows_message(rc);

    return rc;
}

static DWORD set_static_ip_address(struct tuntap_dev* device) {
    ULONG NTEContext, NTEInstance;
    DWORD rc;
    rc = AddIPAddress(
        (IPAddr)device->ip_addr,
        (IPAddr)device->device_mask,
        device->ifIdx, &NTEContext, &NTEInstance
    );


    switch (rc) {
        /* ip already set */
        case ERROR_OBJECT_ALREADY_EXISTS:
            return 0;
        default:
            return rc;
    }
}

int open_wintap(struct tuntap_dev *device,
                const char * address_mode, /* "static" or "dhcp" */
                char *device_ip, 
                char *device_mask,
                const char *device_mac, 
                int mtu) {
    HKEY key, key2;
    LONG rc;
    WCHAR regpath[1024];
    WCHAR adapterid[1024];
    WCHAR tapname[1024];
    long len;
    int found = 0;
    int i;
    ULONG status = TRUE;

    memset(device, 0, sizeof(struct tuntap_dev));
    device->device_handle = INVALID_HANDLE_VALUE;
    device->device_name = NULL;
    device->ifIdx = NET_IFINDEX_UNSPECIFIED;

    if (inet_pton(AF_INET, device_ip, &device->ip_addr) != 1) {
        printf("device ip is not a valid IP address\n");
        exit(-1);
    }

    if (inet_pton(AF_INET, device_mask, &device->device_mask) != 1) {
        printf("net mask is not a valid\n");
        exit(-1);
    }

    /* Open registry and look for network adapters */
    if((rc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEY, 0, KEY_READ, &key))) {
        printf("Unable to read registry: [rc=%d]\n", rc);
        exit(-1);
        /* MSVC Note: If you keep getting rc=2 errors, make sure you set:
         * Project -> Properties -> Configuration Properties -> General -> Character set
         * to: "Use Multi-Byte Character Set"
         */
    }

    for (i = 0; ; i++) {
        len = sizeof(adapterid);
        if(RegEnumKeyEx(key, i, adapterid, &len, 0, 0, 0, NULL))
            break;

        /* Find out more about this adapter */
        _snwprintf(regpath, sizeof(regpath), NETWORK_CONNECTIONS_KEY L"\\%s\\Connection", adapterid);
        if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, regpath, 0, KEY_READ, &key2))
            continue;

        RegCloseKey(key2);

        if(device->device_name) {
            if(!wcscmp(device->device_name, adapterid)) {
                found = 1;
                break;
            } else
                continue;
        }

        _snwprintf(tapname, sizeof(tapname), USERMODEDEVICEDIR "%s" TAPSUFFIX, adapterid);
        device->device_handle = CreateFile(tapname, GENERIC_WRITE | GENERIC_READ,
                                           0, /* Don't let other processes share or open the resource until the handle's been closed */
                                           0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
        if(device->device_handle != INVALID_HANDLE_VALUE) {
            found = 1;
            break;
        }
    }

    RegCloseKey(key);

    if(!found) {
        printf("No Windows tap device found!\n");
        exit(0);
    }

    /* ************************************** */

    if(!device->device_name)
        device->device_name = _wcsdup(adapterid);

     if(device->ifIdx == NET_IFINDEX_UNSPECIFIED) {
        device->ifIdx = get_adapter_index(adapterid);
    }

    /* Try to open the corresponding tap device->device_name */

    if(device->device_handle == INVALID_HANDLE_VALUE) {
        _snwprintf(tapname, sizeof(tapname), USERMODEDEVICEDIR "%s" TAPSUFFIX, device->device_name);
        device->device_handle = CreateFile(tapname, GENERIC_WRITE | GENERIC_READ, 0, 0,
                                           OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
    }

    if(device->device_handle == INVALID_HANDLE_VALUE) {
        printf("%ls is not a usable Windows tap device\n", device->device_name);
        exit(-1);
    }

    /* Get MAC address from tap device->device_name */
    if(!DeviceIoControl(device->device_handle, TAP_IOCTL_GET_MAC,
                        device->mac_addr, sizeof(device->mac_addr),
                        device->mac_addr, sizeof(device->mac_addr), &len, 0)) {
        printf("Could not get MAC address from Windows tap %ls\n", device->device_name);
        return -1;
    }

    device->mtu = mtu;

    printf("Open device [name=%ls][ip=%s][ifIdx=%u][MTU=%d][mac=%02X:%02X:%02X:%02X:%02X:%02X]\n",
           device->device_name, device_ip, device->ifIdx, device->mtu,
           device->mac_addr[0] & 0xFF,
           device->mac_addr[1] & 0xFF,
           device->mac_addr[2] & 0xFF,
           device->mac_addr[3] & 0xFF,
           device->mac_addr[4] & 0xFF,
           device->mac_addr[5] & 0xFF);

    /* ****************** */

    printf("Setting %ls device address...\n", device->device_name);

    if ( 0 == strcmp("dhcp", address_mode) )
    {
        rc = set_dhcp(device);
        tuntap_get_address(device);
    }
    else
    {        
        rc = set_static_ip_address(device);
    }

    if (rc == 0) {
        char buffer[16], buffer2[16];
        printf("Device %ls set to %s/%s\n", 
            device->device_name,
            inet_ntop(AF_INET, &device->ip_addr, buffer, 16),
            inet_ntop(AF_INET, &device->device_mask, buffer2, 16)
        );
    } else
        printf("WARNING: Unable to set device %ls IP address [rc=%u]\n", device->device_name, rc);

    /* ****************** */

    if(device->mtu != DEFAULT_MTU)
        printf("WARNING: MTU set is not supported on Windows\n");

    /* set driver media status to 'connected' (i.e. set the interface up) */
    if (!DeviceIoControl (device->device_handle, TAP_IOCTL_SET_MEDIA_STATUS,
                          &status, sizeof (status),
                          &status, sizeof (status), &len, NULL))
        printf("WARNING: Unable to enable TAP adapter\n");

    /*
    * Initialize overlapped structures
    */
    device->overlap_read.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    device->overlap_write.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!device->overlap_read.hEvent || !device->overlap_write.hEvent) {
        return -1;
    }

    return(0);
}

/* ************************************************ */

ssize_t tuntap_read(struct tuntap_dev *tuntap, unsigned char *buf, size_t len) {
    DWORD read_size, last_err;

    ResetEvent(tuntap->overlap_read.hEvent);
    if (ReadFile(tuntap->device_handle, buf, (DWORD) len, &read_size, &tuntap->overlap_read)) {
        //printf("tun_read(len=%d)\n", read_size);
        return (ssize_t) read_size;
    }
    switch (last_err = GetLastError()) {
    case ERROR_IO_PENDING:
        WaitForSingleObject(tuntap->overlap_read.hEvent, INFINITE);
        GetOverlappedResult(tuntap->device_handle, &tuntap->overlap_read, &read_size, FALSE);
        return (ssize_t) read_size;
        break;
    default:
        printf("GetLastError() returned %d\n", last_err);
        break;
    }

  return -1;
}
/* ************************************************ */

ssize_t tuntap_write(struct tuntap_dev *tuntap, unsigned char *buf, size_t len) {
    DWORD write_size;

    //printf("tun_write(len=%d)\n", len);

    ResetEvent(tuntap->overlap_write.hEvent);
    if (WriteFile(tuntap->device_handle,
        buf,
        (DWORD) len,
        &write_size,
        &tuntap->overlap_write))
    {
        //printf("DONE tun_write(len=%d)\n", write_size);
        return (ssize_t) write_size;
    }

    switch (GetLastError()) {
    case ERROR_IO_PENDING:
        WaitForSingleObject(tuntap->overlap_write.hEvent, INFINITE);
        GetOverlappedResult(tuntap->device_handle, &tuntap->overlap_write, &write_size, FALSE);
        return (ssize_t) write_size;
        break;
    default:
        break;
    }

  return -1;
}

/* ************************************************ */

int tuntap_open(struct tuntap_dev *device, 
                char *dev, 
                const char *address_mode, /* static or dhcp */
                char *device_ip, 
                char *device_mask, 
                const char * device_mac, 
                int mtu) {
    return(open_wintap(device, address_mode, device_ip, device_mask, device_mac, mtu));
}

/* ************************************************ */

void tuntap_close(struct tuntap_dev *tuntap) {
    CloseHandle(tuntap->device_handle);
}

/* Fill out the ip_addr value from the interface. Called to pick up dynamic
 * address changes. */
void tuntap_get_address(struct tuntap_dev *tuntap) {
    PMIB_IPADDRTABLE addr_table;
    ULONG size;
    
    if (GetIpAddrTable(NULL, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER)
        return;
    if ((addr_table = malloc(size)) == NULL)
        return;
    if (GetIpAddrTable(addr_table, &size, FALSE) != NO_ERROR)
        return;
    for (DWORD i=0; i < addr_table->dwNumEntries; i++) {
        if (addr_table->table[i].dwIndex == tuntap->ifIdx) {
            tuntap->ip_addr = addr_table->table[i].dwAddr;
            tuntap->device_mask = addr_table->table[i].dwMask;
        }
    }
    free(addr_table);
}
/* ************************************************ */

#if 0
int main(int argc, char* argv[]) {
    struct tuntap_dev tuntap;
    int i;
    int mtu = 1400;

    printf("Welcome to n2n\n");
    initWin32();
    open_wintap(&tuntap, "dhcp", "0.0.0.0", NULL, NULL, mtu);
    tuntap_get_address(&tuntap);
    for(i=0; i<10; i++) {
        u_char buf[MTU];
        int rc;

        rc = tuntap_read(&tuntap, buf, sizeof(buf));
        buf[0]=2;
        buf[1]=3;
        buf[2]=4;

        printf("tun_read returned %d\n", rc);
        rc = tuntap_write(&tuntap, buf, rc);
        printf("tun_write returned %d\n", rc);
    }
    Sleep(10000);
    // rc = tun_open (device->device_name, IF_MODE_TUN);
    WSACleanup ();
    return(0);
}

#endif
