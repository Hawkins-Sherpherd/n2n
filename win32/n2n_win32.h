/*

	(C) 2007-09 - Luca Deri <deri@ntop.org>

*/

#ifndef _N2N_WIN32_H_
#define _N2N_WIN32_H_

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE

/* use our own definition for min/max */
#define NOMINMAX

/* use windows unicode API */
#define UNICODE
#define _UNICODE

#if defined(__MINGW32__)
/* should be defined here and before winsock gets included */
#define _WIN32_WINNT 0x501 //Otherwise the linker doesnt find getaddrinfo
#include <inttypes.h>
#endif /* #if defined(__MINGW32__) */

#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>

/* ip helper api */
#include <iphlpapi.h>

/* for CLSIDFromString */
#include <objbase.h>

/* for _access */
#include <io.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ole32.lib")
#endif

#include "wintap.h"

#include <stdint.h>
#ifdef _MSC_VER
#include "getopt.h"

#ifdef _WIN64
typedef __int64 ssize_t;
#else
typedef long ssize_t;
#endif
#endif /* #ifdef _MSC_VER */

#define access _access
#define R_OK 4

typedef unsigned long in_addr_t;

#ifdef EAFNOSUPPORT
#undef EAFNOSUPPORT
#endif
#define EAFNOSUPPORT   WSAEAFNOSUPPORT

#define socklen_t int

#define ETH_ADDR_LEN 6
/*                                                                                                                                                                                     
 * Structure of a 10Mb/s Ethernet header.                                                                                                                                              
 */
struct ether_hdr
{
    uint8_t  dhost[ETH_ADDR_LEN];
    uint8_t  shost[ETH_ADDR_LEN];
    uint16_t type;                /* higher layer protocol encapsulated */
};

typedef struct ether_hdr ether_hdr_t;

/* ************************************* */

struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN
        u_char  ip_hl:4,                /* header length */
                ip_v:4;                 /* version */
#else
        u_char  ip_v:4,                 /* version */
                ip_hl:4;                /* header length */
#endif
        u_char  ip_tos;                 /* type of service */
        short   ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        short   ip_off;                 /* fragment offset field */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};


/* ************************************* */

typedef struct tuntap_dev {
	HANDLE device_handle;
	WCHAR  device_name[40]; /* legnth of a CLSID is 38 */
	NET_IFINDEX  ifIdx;
        NET_LUID luid;
	OVERLAPPED overlap_read, overlap_write;
	uint8_t      mac_addr[6];
	uint32_t     ip_addr, device_mask;
        struct in6_addr ip6_addr;
        uint8_t      ip6_prefixlen;
	unsigned int mtu;
} tuntap_dev;

#define W32_ERROR(rc, error_string) \
        LPTSTR error_string = NULL; \
        FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,\
            NULL, rc, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &error_string, 0,NULL );
#define W32_ERROR_FREE(error_string) LocalFree( error_string );

extern HANDLE event_log;

extern wchar_t scm_name[16];

void initWin32();

int scm_startup(wchar_t* name);

#endif
