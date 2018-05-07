/*
  (C) 2007-09 - Luca Deri <deri@ntop.org>
*/

#include "../n2n.h"
#include "n2n_win32.h"

/* 1500 bytes payload + 14 bytes ethernet header + 4 bytes VLAN tag */
#define MTU 1518

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

static int get_adapter_luid(PWSTR device_name, NET_LUID* luid) {
    CLSID guid;

    if (CLSIDFromString(device_name, &guid) != NO_ERROR)
        return -1;
    
    if (ConvertInterfaceGuidToLuid(&guid, luid) != NO_ERROR)
        return -1;

    return 0;
}

static DWORD set_dhcp(struct tuntap_dev* device) {
    WCHAR if_name[MAX_ADAPTER_NAME_LENGTH];
    WCHAR windows_path[64], cmd[128], netsh[256];
    DWORD rc;
    SHELLEXECUTEINFO shex;

    ConvertInterfaceLuidToNameW(&device->luid, if_name, MAX_ADAPTER_NAME_LENGTH);
    GetEnvironmentVariable(L"SystemRoot", windows_path, 256);

    _snwprintf(cmd, 256, L"%s\\system32\\netsh.exe", windows_path);
    _snwprintf(netsh, 1024, L"interface ipv4 set address %s dhcp", if_name);
    memset( &shex, 0, sizeof(SHELLEXECUTEINFO) );

    shex.cbSize       = sizeof( SHELLEXECUTEINFO );
    shex.fMask        = 0;
    shex.lpVerb       = L"runas";
    shex.lpFile       = cmd;
    shex.lpParameters = netsh;

    rc = ShellExecuteEx(&shex);

    // print_windows_message(GetLastError());

    return 0;
}

static DWORD set_static_ip_address(struct tuntap_dev* device) {
#if 0
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
#endif
    WCHAR if_name[MAX_ADAPTER_NAME_LENGTH];
    WCHAR windows_path[64], cmd[128], netsh[256];
    char ip[INET6_ADDRSTRLEN], mask[INET_ADDRSTRLEN];
    SHELLEXECUTEINFO shex;
    DWORD rc;

    ConvertInterfaceLuidToNameW(&device->luid, if_name, MAX_ADAPTER_NAME_LENGTH);
    GetEnvironmentVariable(L"SystemRoot", windows_path, 256);
    inet_ntop(AF_INET, &device->ip_addr, ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &device->device_mask, mask, INET_ADDRSTRLEN);

    _snwprintf(cmd, 256, L"%s\\system32\\netsh.exe", windows_path);
    _snwprintf(netsh, 1024, L"interface ipv4 set address %s static %hs %hs", if_name, ip, mask);
    memset( &shex, 0, sizeof(SHELLEXECUTEINFO) );

    shex.cbSize       = sizeof( SHELLEXECUTEINFO );
    shex.fMask        = SEE_MASK_NO_CONSOLE | SEE_MASK_NOASYNC;
    shex.lpVerb       = L"runas";
    shex.lpFile       = cmd;
    shex.lpParameters = netsh;

    rc = ShellExecuteEx(&shex);

    inet_ntop(AF_INET6, &device->ip6_addr, ip, INET6_ADDRSTRLEN);
    _snwprintf(netsh, 1024, L"interface ipv6 set address %s %hs/%hu", if_name, ip, device->ip6_prefixlen);
    printf("%ls\n", netsh);
    memset( &shex, 0, sizeof(SHELLEXECUTEINFO) );

    shex.cbSize       = sizeof( SHELLEXECUTEINFO );
    shex.fMask        = SEE_MASK_NO_CONSOLE | SEE_MASK_NOASYNC;
    shex.lpVerb       = L"runas";
    shex.lpFile       = cmd;
    shex.lpParameters = netsh;

    rc = ShellExecuteEx(&shex);

    return 0;
}

int tuntap_open(struct tuntap_dev *device, struct tuntap_config* config) {
    HKEY key, key2;
    LONG rc;
    WCHAR regpath[1024];
    WCHAR adapterid[1024];
    WCHAR tapname[1024];
    char ip_address[INET6_ADDRSTRLEN];
    long len;
    int found = 0;
    int i;
    ULONG status = TRUE;

    memset(device, 0, sizeof(struct tuntap_dev));
    device->device_handle = INVALID_HANDLE_VALUE;
    device->device_name = NULL;
    device->ifIdx = NET_IFINDEX_UNSPECIFIED;

    memset(&device->luid, 0, sizeof(NET_LUID));

    memcpy(&device->ip_addr, &config->ip_addr, sizeof(config->ip_addr));
    memcpy(&device->device_mask, &config->netmask, sizeof(config->netmask));
    memcpy(&device->ip6_addr, &config->ip6_addr, sizeof(config->ip6_addr));
    device->ip6_prefixlen = config->ip6_prefixlen;
    device->mtu = config->mtu;

    /* Open registry and look for network adapters */
    if((rc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEY, 0, KEY_READ, &key))) {
        printf("Unable to read registry: [rc=%d]\n", rc);
        exit(-1);
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

        _snwprintf(tapname, sizeof(tapname), USERMODEDEVICEDIR L"%s" TAP_WIN_SUFFIX, adapterid);
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
        if (get_adapter_luid(adapterid, &device->luid) == 0) {
            IF_INDEX index = NET_IFINDEX_UNSPECIFIED;
            if (ConvertInterfaceLuidToIndex(&device->luid, &index) == 0) {
                device->ifIdx = index;
            }
        }
    }

    /* Try to open the corresponding tap device->device_name */

    if(device->device_handle == INVALID_HANDLE_VALUE) {
        _snwprintf(tapname, sizeof(tapname), USERMODEDEVICEDIR "%s" TAP_WIN_SUFFIX, device->device_name);
        device->device_handle = CreateFile(tapname, GENERIC_WRITE | GENERIC_READ, 0, 0,
                                           OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
    }

    if(device->device_handle == INVALID_HANDLE_VALUE) {
        printf("%ls is not a usable Windows tap device\n", device->device_name);
        exit(-1);
    }

    /* Get MAC address from tap device->device_name */
    if(!DeviceIoControl(device->device_handle, TAP_WIN_IOCTL_GET_MAC,
                        device->mac_addr, sizeof(device->mac_addr),
                        device->mac_addr, sizeof(device->mac_addr), &len, 0)) {
        printf("Could not get MAC address from Windows tap %ls\n", device->device_name);
        return -1;
    }

    printf("Open device [name=%ls][ip=%s][ifIdx=%u][MTU=%d][mac=%02X:%02X:%02X:%02X:%02X:%02X]\n",
           device->device_name,
           inet_ntop(AF_INET, &device->ip_addr, (PSTR) &ip_address, INET_ADDRSTRLEN),
           device->ifIdx, device->mtu,
           device->mac_addr[0] & 0xFF,
           device->mac_addr[1] & 0xFF,
           device->mac_addr[2] & 0xFF,
           device->mac_addr[3] & 0xFF,
           device->mac_addr[4] & 0xFF,
           device->mac_addr[5] & 0xFF);

    /* ****************** */

    printf("Setting %ls device address...\n", device->device_name);

    if (config->dyn_ip4)
    {
        rc = set_dhcp(device);
    }
    else
    {        
        rc = set_static_ip_address(device);
    }

    if (rc == 0) {
        tuntap_get_address(device);
    } else
        printf("WARNING: Unable to set device %ls IP address [rc=%u]\n", device->device_name, rc);

    /* ****************** */

    if(device->mtu != DEFAULT_MTU)
        printf("WARNING: MTU set is not supported on Windows\n");

    /* set driver media status to 'connected' (i.e. set the interface up) */
    if (!DeviceIoControl (device->device_handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
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

void tuntap_close(struct tuntap_dev *tuntap) {
    if (tuntap->device_name) {
        free( tuntap->device_name );
        tuntap->device_name = NULL;
    }
    CloseHandle(tuntap->device_handle);
}

/* Fill out the ip_addr value from the interface. Called to pick up dynamic
 * address changes. */
void tuntap_get_address(struct tuntap_dev *tuntap) {
    char buffer[16], buffer2[16];
    IP_ADAPTER_ADDRESSES* adapter_list;
    ULONG size = 0;

    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_FRIENDLY_NAME, NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW)
        return;
    adapter_list = malloc (size);

    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_FRIENDLY_NAME, NULL, adapter_list, &size) != NO_ERROR) {
        free(adapter_list);
        return;
    }

    IP_ADAPTER_ADDRESSES* adapter = adapter_list;
    while (adapter) {
        if (adapter->IfIndex == tuntap->ifIdx) {
            IP_ADAPTER_UNICAST_ADDRESS* uni = adapter->FirstUnicastAddress;
            while (uni) {
                /* skip LL-addresses */
                if (uni->SuffixOrigin == IpSuffixOriginLinkLayerAddress) {
                    uni = uni->Next;
                    continue;
                }

                memcpy(&tuntap->ip_addr, &((struct sockaddr_in*) uni->Address.lpSockaddr)->sin_addr, 4);
                uint32_t mask = 0x0000;
                for (int i = uni->OnLinkPrefixLength; i--;)
                    mask = ((mask | 0x8000) | mask >> 1);
                uni = uni->Next;
            }
            
            break;
        }
        adapter = adapter->Next;
    }

    free(adapter_list);
    printf("Device %ls set to %s/%s\n",
        tuntap->device_name,
        inet_ntop(AF_INET, &tuntap->ip_addr, buffer, 16),
        inet_ntop(AF_INET, &tuntap->device_mask, buffer2, 16)
    );
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
