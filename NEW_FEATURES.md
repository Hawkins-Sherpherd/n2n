
Between 2.0.x and 2.1.x

* Better ming Windows build support.
* Added -E flag to allow multicast ethernet traffic.

Further Additions:
* Windows User Access Control
* Windows Service (and Windows Event Log)
* Specifying which Windows TAP adapter to use using `-d`
* Linux capability awareness
* Use API on Windows (IPHLPAPI.DLL) and Linux (ioctl) to set IP address
* AES uses EVP for Hardware acceleration instead of pure software implementation
* IPv6 support

Future:
* NetBSD/FreeBSD/MacOS (most definitley broken, never checked)
* Other Ciphers
* Better Documentation
* Code cleanup
