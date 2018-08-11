
Between 2.0.x and 2.1.x

* Better ming Windows build support.
* Added -E flag to allow multicast ethernet traffic.

Further Additions:
* Windows User Access Control
* Windows Service (and Windows Event Log)
* Specifying which Windows TAP adapter to use using `-d`
* Linux capability awareness
* Use API on Windows (IPHLPAPI.DLL) and Linux (ioctl) to set IP address
* AES can use several crypto implementations:
  - OpenSSL
  - mbedTLS (default for OpenWRT)
  - nettle (low level library for GnuTLS)
  - gcrypt (part of GnuPG)
  - bcrypt.dll (Microsoft NextGen Crypto API, Part of Windows Vista and up)
  - libell (Embeded Linux Library, uses Kernel for Cryptography support)
* IPv6 support

Future:
* NetBSD/FreeBSD/MacOS (most definitley broken, never checked)
* Other Ciphers
* Better Documentation
* Code cleanup
