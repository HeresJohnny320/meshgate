// Kernel-control definitions used to find the utun file descriptor that
// NEPacketTunnelProvider created. iOS does not expose these headers to Swift
// (same approach as WireGuardKit).
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define CTLIOCGINFO 0xc0644e03UL
struct ctl_info {
    u_int32_t ctl_id;
    char ctl_name[96];
};
struct sockaddr_ctl {
    u_char sc_len;
    u_char sc_family;
    u_int16_t ss_sysaddr;
    u_int32_t sc_id;
    u_int32_t sc_unit;
    u_int32_t sc_reserved[5];
};
