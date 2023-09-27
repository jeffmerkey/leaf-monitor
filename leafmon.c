/***************************************************************************
*
*   Copyright(c) Jeff V. Merkey 1997-2020.  All rights reserved.
*   Open CWorthy Look Alike Terminal Library.  Licensed under the 
*   Lesser GPL License v2.1
*
*   LEAFCON c-icap-leaf server monitor program
*
**************************************************************************/

#define __GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <semaphore.h>
#include <sys/mman.h>

#include <ctype.h>
#include <regex.h>

#include "cworthy.h"
#include "srv_stats.h"

#include <sys/vfs.h>
#include <sys/statvfs.h>

#define IPV6_ADDR_ANY		0x0000U
#define IPV6_ADDR_UNICAST	0x0001U
#define IPV6_ADDR_MULTICAST	0x0002U
#define IPV6_ADDR_ANYCAST	0x0004U
#define IPV6_ADDR_LOOPBACK	0x0010U
#define IPV6_ADDR_LINKLOCAL	0x0020U
#define IPV6_ADDR_SITELOCAL	0x0040U
#define IPV6_ADDR_COMPATv4	0x0080U
#define IPV6_ADDR_SCOPE_MASK	0x00f0U
#define IPV6_ADDR_MAPPED	0x1000U
#define IPV6_ADDR_RESERVED	0x2000U

#define NUD_INCOMPLETE  0x01
#define NUD_REACHABLE   0x02
#define NUD_STALE       0x04
#define NUD_DELAY       0x08
#define NUD_PROBE       0x10
#define NUD_FAILED      0x20

#define NUD_NOARP       0x40
#define NUD_PERMANENT   0x80
#define NUD_NONE        0x00

#define NTF_PROXY       0x08
#define NTF_ROUTER      0x80
#define NTF_02          0x02
#define NTF_04          0x04

#define MAX_CPUS  64

typedef struct _STATE
{
    int cpus;
    unsigned long long total_usr;
    unsigned long long total_sys;
    unsigned long long total_nice;
    unsigned long long total_idle;
    unsigned long long total_io;
    unsigned long long total_irq;
    unsigned long long total_sirq;
    unsigned long long usr[MAX_CPUS];
    unsigned long long sys[MAX_CPUS];
    unsigned long long nice[MAX_CPUS];
    unsigned long long idle[MAX_CPUS];
    unsigned long long io[MAX_CPUS];
    unsigned long long irq[MAX_CPUS];
    unsigned long long sirq[MAX_CPUS];
} STATE;

#include <linux/major.h>

#ifndef IDE_DISK_MAJOR
#define IDE_DISK_MAJOR(M) ((M) == IDE0_MAJOR || (M) == IDE1_MAJOR || \
			   (M) == IDE2_MAJOR || (M) == IDE3_MAJOR || \
			   (M) == IDE4_MAJOR || (M) == IDE5_MAJOR || \
			   (M) == IDE6_MAJOR || (M) == IDE7_MAJOR || \
			   (M) == IDE8_MAJOR || (M) == IDE9_MAJOR)
#endif

#ifndef SCSI_DISK_MAJOR
#ifndef SCSI_DISK8_MAJOR
#define SCSI_DISK8_MAJOR 128
#endif
#ifndef SCSI_DISK15_MAJOR
#define SCSI_DISK15_MAJOR 135
#endif
#define SCSI_DISK_MAJOR(M) ((M) == SCSI_DISK0_MAJOR || \
			   ((M) >= SCSI_DISK1_MAJOR && \
			    (M) <= SCSI_DISK7_MAJOR) || \
			   ((M) >= SCSI_DISK8_MAJOR && \
			    (M) <= SCSI_DISK15_MAJOR))
#endif

int detect_disk(int major, int minor)
{
	if (IDE_DISK_MAJOR(major)) {
		return (!(minor & 0x3F));
	}
	else if (SCSI_DISK_MAJOR(major)) {
		return (!(minor & 0x0F));
	}
	return 1;
}

#define MAX_PARTITIONS 256

typedef struct _part_stats {
	int n_part;
	unsigned long long total_reads;
	unsigned long long total_reads_merged;
	unsigned long long total_sectors_read;
	unsigned long long total_read_time;
	unsigned long long total_writes;
	unsigned long long total_writes_merged;
	unsigned long long total_sectors_written;
	unsigned long long total_write_time;
	unsigned long long total_io_active;
	unsigned long long total_io_time;
	unsigned long long total_io_weight;
	unsigned long long total_p_read;
	unsigned long long total_p_written;
	unsigned long long total_p_iotime;
	unsigned long long total_p_read_time;
	unsigned long long total_p_write_time;
	unsigned long long total_p_io_active;
	unsigned long long total_p_io_weight;
	struct _partitions {
		int major;
		int minor;
		char device_name[256];
		unsigned long long reads;
		unsigned long long reads_merged;
		unsigned long long sectors_read;
		unsigned long long read_time;
		unsigned long long writes;
		unsigned long long writes_merged;
		unsigned long long sectors_written;
		unsigned long long write_time;
		unsigned long long io_active;
		unsigned long long io_time;
		unsigned long long io_weight;
		unsigned long long p_read;
		unsigned long long p_written;
		unsigned long long p_iotime;
		unsigned long long p_read_time;
		unsigned long long p_write_time;
		unsigned long long p_io_active;
		unsigned long long p_io_weight;
	} p[MAX_PARTITIONS];
} PSTATE;


struct user_net_device_stats {
    struct user_net_device_stats *next;
    struct user_net_device_stats *prior;
    unsigned long long rx_packets;	/* total packets received       */
    unsigned long long tx_packets;	/* total packets transmitted    */
    unsigned long long rx_bytes;	/* total bytes received         */
    unsigned long long tx_bytes;	/* total bytes transmitted      */
    unsigned long long p_rx_packets;	/* previous packets received       */
    unsigned long long p_tx_packets;	/* previous packets transmitted    */
    unsigned long long p_rx_bytes;	/* previous bytes received         */
    unsigned long long p_tx_bytes;	/* previous bytes transmitted      */
    unsigned long rx_errors;	/* bad packets received         */
    unsigned long tx_errors;	/* packet transmit problems     */
    unsigned long rx_dropped;	/* no space in linux buffers    */
    unsigned long tx_dropped;	/* no space available in linux  */
    unsigned long rx_multicast;	/* multicast packets received   */
    unsigned long rx_compressed;
    unsigned long tx_compressed;
    unsigned long collisions;

    /* detailed rx_errors: */
    unsigned long rx_length_errors;
    unsigned long rx_over_errors;	/* receiver ring buff overflow  */
    unsigned long rx_crc_errors;	/* recved pkt with crc error    */
    unsigned long rx_frame_errors;	/* recv'd frame alignment error */
    unsigned long rx_fifo_errors;	/* recv'r fifo overrun          */
    unsigned long rx_missed_errors;	/* receiver missed packet     */
    /* detailed tx_errors */
    unsigned long tx_aborted_errors;
    unsigned long tx_carrier_errors;
    unsigned long tx_fifo_errors;
    unsigned long tx_heartbeat_errors;
    unsigned long tx_window_errors;
    char ifname[IFNAMSIZ+1];
};

struct net_stats_list {
    struct user_net_device_stats *head;
    struct user_net_device_stats *tail;
    struct user_net_device_stats *current;
    struct user_net_device_stats *previous;
};

typedef struct leaf_context {
	unsigned long long pages_per_second;
	unsigned long long bytes_per_second;
	unsigned long long errors_per_second;
	unsigned long long dropped_per_second;
	unsigned long long aborts_per_second;
	unsigned long long skipped_per_second;
	unsigned long long total_pages;
	unsigned long long total_bytes;
	unsigned long long total_errors;
	unsigned long long total_dropped;
	unsigned long long total_aborts;
	unsigned long long total_skipped;
	unsigned long long total_allocation;
	unsigned long long total_process;
	unsigned long long total_connection;
	unsigned long long total_queue;
	unsigned long long peak_pages_per_second;
	unsigned long long peak_bytes_per_second;
	unsigned long long peak_errors_per_second;
	unsigned long long peak_dropped_per_second;
	unsigned long long peak_aborts_per_second;
	unsigned long long peak_skipped_per_second;
	unsigned long long avg_pages_per_second;
	unsigned long long avg_bytes_per_second;
	unsigned long long avg_errors_per_second;
	unsigned long long avg_dropped_per_second;
	unsigned long long avg_aborts_per_second;
	unsigned long long avg_skipped_per_second;
	char db_host[MAX_SQL_HOSTNAME+1];
	char db_name[MAX_SQL_DATABASE_NAME+1];
	char db_table[MAX_SQL_TABLE_NAME+1];
	char db_user[MAX_SQL_USER_NAME+1];
	char db_pass[MAX_SQL_PASSWORD+1];
	char db_path[MAX_PATH_LENGTH+1];
        unsigned long db_free_space_threshold;
	unsigned long db_max_size;
	unsigned long skip_length;
	unsigned long condensed_max_length;
        unsigned long async_threads;
        unsigned long sync_threads;
	int show_skipped_requests;
	int db_mode;
	int db_init_startup;
	unsigned long long license;
        unsigned char license_data[128];
} LCTX;

typedef struct nparam {
   int portal;
   STATE *state;
   PSTATE *pstate;
   LCTX *ctx;
   struct net_stats_list list;
   char ifname[IFNAMSIZ+1];
} NP;

int active = 0;
int netsumactive = 0;
int networkactive = 0;
int menu, mainportal, logportal = -1;
int leafsumactive = 0;
int leafdiskactive = 0;
int cicapactive = 0;
int mysqlactive = 0;
pthread_t pstat;
pthread_t netsumstat;
pthread_t networkstat;
pthread_t diskstat;
pthread_t cicapstat;
pthread_t mysqlstat;

char mysql_datadir[4096+1] = { "/var/lib/mysql" };

unsigned long long mysql_free_size(void)
{
	char buffer[1024];
	FILE *fp;
	unsigned long long len = 0, flag = 0;

	fp = fopen("/etc/my.cnf", "rb");
	while (fp && !feof(fp))
	{
		if (fgets(buffer, 1024, fp)) 
		{
			int count;
			char temp[1024], *src, *dest;
			temp[0] = '\0';
			count = 0;
			src = buffer;
			dest = temp;

			// strip out all spaces and punc characters
			while (*src) {
				if (++count > 1024)
					break;
				if ((*src == '\n') || (*src == ' ') || (*src == '\t') ||
					 (*src == '\r') || (*src == ';') || (*src == ',')) {
					src++;
				}
				else				
					*dest++ = *src++;
			}
			*dest = '\0';

			// skip empty lines
			if (!temp[0])
				continue;

			// skip comments
			if (!strncasecmp(temp, "#", 1))
				continue;

			if (!strncasecmp(temp, "[mysqld]", 8)) {
				flag++;
			}
			else if (!strncasecmp(temp, "datadir=", 8) && flag) {
				flag = 0;
				strncpy(mysql_datadir, &temp[8], 4096+1);
    				struct statvfs stat;
				if (!statvfs(mysql_datadir, &stat)) {
					len = (unsigned long long)stat.f_bavail * stat.f_frsize;
					fclose(fp);
					return len;
				}
			}
			else if (!strncasecmp(temp, "[", 1)) {
				// if new section, clear mysqld flag
				flag = 0;
			}
		}
	}
	if (fp) {
		fclose(fp);
	}

	struct statvfs stat;
	if (!statvfs(mysql_datadir, &stat)) {
		len = (unsigned long long)stat.f_bavail * stat.f_frsize;
		return len;
	}
	return len;

}

char *comma_snprintf(char *buffer, int size, const char *format, ...)
{
    register unsigned int len, i;
    char buf[1024], *src, *dest;
    register size_t vsize = size > (1024 - 1) ? 1024 - 1 : size;
    va_list ap;

    va_start(ap, format);
    len = vsnprintf((char *)buf, vsize, format, ap);
    va_end(ap);

    if (len)
    {
       src = buf + strlen((const char *)buf);
       dest = buffer + vsize;
       *dest = '\0';
       for (i=0; (i < strlen((const char *)buf)) &&
            (dest >= buffer) && (src >= buf); i++)
       {
          if (i && !(i % 3))
             *--dest = ',';
          *--dest = *--src;
       }
       return (char *)dest;
    }
    return (char *)"";
}

// scaled chars for kilobyte, megabyte, gigabyte, terabyte,
// petabyte, exabyte, zettabyte, and yottabyte
char scale_chars[]={ 'K','M','G','T','P','E','Z','Y', };
char *comma_snprintf_scaled(char *buffer, int size, const char *format, unsigned long long value, unsigned int width)
{
    register unsigned int len, i;
    char buf[1024], *src, *dest, ch = '\0';
    register size_t vsize = size > (1024 - 1) ? 1024 - 1 : size;

    // NOTE:  the width specified should be -4 less than display size
    len = snprintf((char *)buf, vsize, format, value);
    if (len)
    {
       int adjlen = len / 3;
       for (i=0; i < sizeof(scale_chars) && ((len + adjlen) > width); i++) {
           ch = scale_chars[i];
           value /= 1000;
           len = snprintf((char *)buf, vsize, format, value);
           adjlen = len / 3;
       }

       src = buf + strlen((const char *)buf);
       dest = buffer + vsize;
       *dest = '\0';
       if (ch) {
          *--dest = 'b';
          *--dest = ch;
          *--dest = ' ';
       }

       register unsigned int buflen = strlen((const char *)buf);
       for (i=0; (i < buflen) && (dest >= buffer) && (src >= buf); i++)
       {
          if (i && !(i % 3))
             *--dest = ',';
          *--dest = *--src;
       }
       return (char *)dest;

    }
    return (char *)"";
}

int get_processors(void)
{
    int cpus = 0;
    cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpus < 1)
        cpus = 1;
    return (cpus);
}

// start of network functions
static int INET6_resolve(char *name, struct sockaddr_in6 *sin6)
{
    struct addrinfo req, *ai;
    int s;

    memset(&req, '\0', sizeof req);
    req.ai_family = AF_INET6;
    if ((s = getaddrinfo(name, NULL, &req, &ai))) {
	return -1;
    }
    memcpy(sin6, ai->ai_addr, sizeof(struct sockaddr_in6));
    freeaddrinfo(ai);
    return (0);
}

#ifndef IN6_IS_ADDR_UNSPECIFIED
#define IN6_IS_ADDR_UNSPECIFIED(a) \
        (((__u32 *) (a))[0] == 0 && ((__u32 *) (a))[1] == 0 && \
         ((__u32 *) (a))[2] == 0 && ((__u32 *) (a))[3] == 0)
#endif


static int INET6_rresolve(char *name, struct sockaddr_in6 *sin6, int numeric)
{
    int s;

    /* Grmpf. -FvK */
    if (sin6->sin6_family != AF_INET6) {
	errno = EAFNOSUPPORT;
	return (-1);
    }
    if (numeric & 0x7FFF) {
	inet_ntop(AF_INET6, &sin6->sin6_addr, name, 80);
	return (0);
    }
    if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
        if (numeric & 0x8000)
	    strcpy(name, "default");
	else
	    strcpy(name, "*");
	return (0);
    }

    if ((s = getnameinfo((struct sockaddr *) sin6, sizeof(struct sockaddr_in6),
			 name, 255 /* !! */ , NULL, 0, 0))) {
	return -1;
    }
    return (0);
}


void INET6_reserror(char *text)
{
    herror(text);
}

char *INET6_print(unsigned char *ptr)
{
    static char name[80];

    inet_ntop(AF_INET6, (struct in6_addr *) ptr, name, 80);
    return name;
}


static char *INET6_sprint(struct sockaddr *sap, int numeric)
{
    static char buf[128];

    if (sap->sa_family == 0xFFFF || sap->sa_family == 0)
	return strncpy(buf, ("[NONE SET]"), sizeof(buf));
    if (INET6_rresolve(buf, (struct sockaddr_in6 *) sap, numeric) != 0)
	return strncpy(buf, ("[UNKNOWN]"), sizeof(buf));
    return (buf);
}

static int INET6_getsock(char *bufp, struct sockaddr *sap)
{
    struct sockaddr_in6 *sin6;

    sin6 = (struct sockaddr_in6 *) sap;
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = 0;

    if (inet_pton(AF_INET6, bufp, sin6->sin6_addr.s6_addr) <= 0)
	return (-1);

    return 16;
}

static int INET6_input(int type, char *bufp, struct sockaddr *sap)
{
    switch (type) {
    case 1:
	return (INET6_getsock(bufp, sap));
    default:
	return (INET6_resolve(bufp, (struct sockaddr_in6 *) sap));
    }
}

#define FLAG_EXT                 3
#define FLAG_NUM_HOST            4
#define FLAG_NUM_PORT            8
#define FLAG_NUM_USER           16
#define FLAG_NUM  (FLAG_NUM_HOST|FLAG_NUM_PORT|FLAG_NUM_USER)
#define FLAG_SYM                32
#define FLAG_CACHE              64
#define FLAG_FIB               128
#define FLAG_VERBOSE           256
#define RTF_UP              0x0001
#define RTF_GATEWAY         0x0002
#define RTF_HOST            0x0004
#define RTF_REINSTATE       0x0008
#define RTF_DYNAMIC         0x0010
#define RTF_MODIFIED        0x0020
#define RTF_MTU             0x0040
#ifndef RTF_MSS
#define RTF_MSS            RTF_MTU
#endif
#define RTF_WINDOW          0x0080
#define RTF_IRTT            0x0100
#define RTF_REJECT          0x0200
#ifndef RTF_DEFAULT
#define RTF_DEFAULT     0x00010000
#endif
#define RTF_ALLONLINK   0x00020000
#ifndef RTF_ADDRCONF
#define RTF_ADDRCONF    0x00040000
#endif
#define RTF_NONEXTHOP   0x00200000
#define RTF_EXPIRES     0x00400000
#define RTF_CACHE       0x01000000
#define RTF_FLOW        0x02000000
#define RTF_POLICY      0x04000000
#define RTF_LOCAL       0x80000000
#define E_NOTFOUND	         8
#define E_SOCK		         7
#define E_LOOKUP	         6
#define E_VERSION	         5
#define E_USAGE		         4
#define E_OPTERR	         3
#define E_INTERN	         2
#define E_NOSUPP	         1

typedef struct _ARPTYPE
{
   int type;
   const char *name;
} ARPTYPE;

ARPTYPE arptype[]={
   0, "NET/ROM Pseudo",
   1, "Ethernet",
   2, "Experimental Ethernet",
   3, "AX.25 Level 2",
   4, "PROnet Token Ring",
   5, "Chaosnet",
   6, "IEEE 802.2 Ethernet/TR/TB",
   7, "ARCnet",
   8, "APPLEtalk",
   15, "Frame Relay DLCI",
   19, "ATM",
   23, "Metricom STRIP",
   24, "IEEE 1394 IPv4 - RFC 2734",
   27, "EUI-64",
   32, "InfiniBand",
   256, "SLIP",
   257, "CSLIP",
   258, "SLIP6",
   259, "CSLIP6",
   260, "Notional KISS",
   264, "ADAPT",
   270, "ROSE",
   271, "CCITT X.25",
   272, "Boards with X.25 in Firmware",
   280, "Controller Area Network",
   512, "PPP",
   513, "Cisco HDLC",
   516, "LAPB",
   517, "Digital's DDCMP Protocol",
   518, "Raw HDLC",
   768, "IPIP Tunnel",
   769, "IP6IP6 Tunnel",
   770, "Frame Relay Access Device",
   771, "SKIP VIF",
   772, "Loopback Device",
   773, "Localtalk Device",
   774, "Fiber Distributed Data Interface",
   775, "AP1000 BIF",
   776, "IPv6-in-IPv4",
   777, "IP over DDP Tunnel",
   778, "GRE over IP",
   779, "PIMSM register Interface",
   780, "High Performance Parallel Interface",
   781, "Nexus 64Mbps Ash",
   782, "Acorn Econet",
   783, "Linux-IrDA",
   784, "Point to Point Fibrechannel",
   785, "Fibrechannel Arbitrated Loop",
   786, "Fibrechannel Public Loop",
   787, "Fibrechannel Fabric",
   788, "Fibrechannel Media Type 788",
   789, "Fibrechannel Media Type 789",
   790, "Fibrechannel Media Type 790",
   791, "Fibrechannel Media Type 791",
   792, "Fibrechannel Media Type 792",
   793, "Fibrechannel Media Type 793",
   794, "Fibrechannel Media Type 794",
   795, "Fibrechannel Media Type 795",
   796, "Fibrechannel Media Type 796",
   797, "Fibrechannel Media Type 797",
   798, "Fibrechannel Media Type 798",
   799, "Fibrechannel Media Type 799",
   800, "Magic Type Ident For TR",
   801, "IEEE 802.11",
   802, "IEEE 802.11 + Prism2 Header",
   803, "IEEE 802.11 + Radiotap Header",
   0xFFFF, "Void Type",
   0xFFFE, "Zero Header Device",
};

const char *get_arp_type(int type)
{
   register unsigned int i;

   for (i=0; i < (sizeof(arptype) / (sizeof(const char *) + sizeof(int)));
        i++)
   {
      if (arptype[i].type == type)
         return arptype[i].name;
   }
   return "Unknown Device";
}


static int ipx_getaddr(int sock, int ft, struct ifreq *ifr)
{
    ((struct sockaddr_ipx *) &ifr->ifr_addr)->sipx_type = ft;
    return ioctl(sock, SIOCGIFADDR, ifr);
}

#if (IPX_NODE_LEN != 6)
#error "IPX_NODE_LEN != 6"
#endif

static char *IPX_print(unsigned char *ptr)
{
    static char buf[64];
    struct sockaddr_ipx *sipx = (struct sockaddr_ipx *) (ptr - 2);
    int t;

    for (t = IPX_NODE_LEN; t; t--)
	if (sipx->sipx_node[t - 1])
	    break;

    if (t && ntohl(sipx->sipx_network))
	snprintf(buf, sizeof(buf), "%08lX:%02X%02X%02X%02X%02X%02X",
		 (long int) ntohl(sipx->sipx_network),
		 (int) sipx->sipx_node[0], (int) sipx->sipx_node[1],
		 (int) sipx->sipx_node[2], (int) sipx->sipx_node[3],
		 (int) sipx->sipx_node[4], (int) sipx->sipx_node[5]);
    else if (!t && ntohl(sipx->sipx_network))
	snprintf(buf, sizeof(buf), "%08lX",
		 (long int) ntohl(sipx->sipx_network));
    else if (t && !ntohl(sipx->sipx_network))
	snprintf(buf, sizeof(buf), "%02X%02X%02X%02X%02X%02X",
		 (int) sipx->sipx_node[0], (int) sipx->sipx_node[1],
		 (int) sipx->sipx_node[2], (int) sipx->sipx_node[3],
		 (int) sipx->sipx_node[4], (int) sipx->sipx_node[5]);
    else
	buf[0] = '\0';
    return (buf);
}

static char *IPX_sprint(struct sockaddr *sap, int numeric)
{
    static char buf[64];

    if (sap->sa_family != AF_IPX)
	return strncpy(buf, ("[NONE SET]"), sizeof(buf));
    return (IPX_print((unsigned char *)sap->sa_data));
}

static char *ddp_print(unsigned char *ptr)
{
    static char buf[64];
    struct sockaddr_at *sat = (struct sockaddr_at *) (ptr - 2);
    snprintf(buf, sizeof(buf), "%d/%d", (int) ntohs(sat->sat_addr.s_net),
	     (int) sat->sat_addr.s_node);
    return (buf);
}

static char *ddp_sprint(struct sockaddr *sap, int numeric)
{
    static char buf[64];

    if (sap->sa_family != AF_APPLETALK)
	return strncpy(buf, ("[NONE SET]"), sizeof(buf));
    return (ddp_print((unsigned char *)sap->sa_data));
}

static char *ec_print(unsigned char *ptr)
{
    static char buf[64];
    struct ec_addr *ec = (struct ec_addr *) ptr;
    snprintf(buf, sizeof(buf), "%d.%d", ec->net, ec->station);
    return buf;
}


static char *ec_sprint(struct sockaddr *sap, int numeric)
{
    struct sockaddr_ec *sec = (struct sockaddr_ec *) sap;

    if (sap->sa_family != AF_ECONET)
	return (char *)"[NONE SET]";

    return ec_print((unsigned char *) &sec->addr);
}

unsigned int clip(int c) { return (c & 0xFF); }

ULONG warn_func(NWSCREEN *screen, ULONG index)
{
    register ULONG mNum, retCode;

    mask_portal(mainportal);

    mNum = make_menu(screen,
		     " Exit LEAFMON ",
		     get_screen_lines() - 12,
		     ((get_screen_cols() - 1) / 2) -
                     ((strlen((const char *)"  Exit IFCON  ") + 2) / 2),
		     2,
		     BORDER_DOUBLE,
		     YELLOW | BGBLUE,
		     YELLOW | BGBLUE,
		     BRITEWHITE | BGBLUE,
		     BRITEWHITE | BGBLUE,
		     0,
		     0,
		     0,
		     TRUE,
		     0);

    add_item_to_menu(mNum, "Yes", 1);
    add_item_to_menu(mNum, "No", 0);

    retCode = activate_menu(mNum);
    if (retCode == (ULONG) -1)
       retCode = 0;

    free_menu(mNum);

    unmask_portal(mainportal);

    return retCode;
}

int pnv = 1;

int get_dev_fields(char *bp, struct user_net_device_stats *stats)
{
    switch (pnv)
   {
    case 3:
	sscanf(bp,
	"%llu %llu %lu %lu %lu %lu %lu %lu %llu %llu %lu %lu %lu %lu %lu %lu",
	       &stats->rx_bytes,
	       &stats->rx_packets,
	       &stats->rx_errors,
	       &stats->rx_dropped,
	       &stats->rx_fifo_errors,
	       &stats->rx_frame_errors,
	       &stats->rx_compressed,
	       &stats->rx_multicast,

	       &stats->tx_bytes,
	       &stats->tx_packets,
	       &stats->tx_errors,
	       &stats->tx_dropped,
	       &stats->tx_fifo_errors,
	       &stats->collisions,
	       &stats->tx_carrier_errors,
	       &stats->tx_compressed);
	break;
    case 2:
	sscanf(bp, "%llu %llu %lu %lu %lu %lu %llu %llu %lu %lu %lu %lu %lu",
	       &stats->rx_bytes,
	       &stats->rx_packets,
	       &stats->rx_errors,
	       &stats->rx_dropped,
	       &stats->rx_fifo_errors,
	       &stats->rx_frame_errors,

	       &stats->tx_bytes,
	       &stats->tx_packets,
	       &stats->tx_errors,
	       &stats->tx_dropped,
	       &stats->tx_fifo_errors,
	       &stats->collisions,
	       &stats->tx_carrier_errors);
	stats->rx_multicast = 0;
	break;
    case 1:
	sscanf(bp, "%llu %lu %lu %lu %lu %llu %lu %lu %lu %lu %lu",
	       &stats->rx_packets,
	       &stats->rx_errors,
	       &stats->rx_dropped,
	       &stats->rx_fifo_errors,
	       &stats->rx_frame_errors,

	       &stats->tx_packets,
	       &stats->tx_errors,
	       &stats->tx_dropped,
	       &stats->tx_fifo_errors,
	       &stats->collisions,
	       &stats->tx_carrier_errors);
	stats->rx_bytes = 0;
	stats->tx_bytes = 0;
	stats->rx_multicast = 0;
	break;
    }
    return 0;
}

struct user_net_device_stats *add_node(struct user_net_device_stats *node, struct net_stats_list *list)
{
    register struct user_net_device_stats *search;

    if (!list) 
	return NULL;

    search = list->head;
    while (search)
    {
       if (!strcmp(search->ifname, node->ifname))
	  return NULL;
       search = search->next;
    }

    if (!list->head)
    {
       list->head = node;
       list->tail = node;
       node->next = node->prior = NULL;
    }
    else
    {
       list->tail->next = node;
       node->next = NULL;
       node->prior = list->tail;
       list->tail = node;
    }
    return node;
}

struct user_net_device_stats *search_nodes(char *ifname, struct net_stats_list *list)
{
    register struct user_net_device_stats *search, *node;

    search = list->head;
    while (search)
    {
       if (!strcmp(search->ifname, ifname))
	  return search;
       search = search->next;
    }

    node = (struct user_net_device_stats *)malloc(sizeof(struct user_net_device_stats));
    if (node) {
       memset(node, 0, sizeof(struct user_net_device_stats));
       strncpy(node->ifname, ifname, IFNAMSIZ);
       if (!add_node(node, list))
          return NULL;
       return node;
    }
    return NULL;
}

void free_node_list(struct net_stats_list *list)
{
    register struct user_net_device_stats *search;

    if (!list) 
	return;

    while (list->head) {
       search = list->head;
       list->head = search->next;
       free(search);
    }
    list->head = list->tail = NULL;
}

int if_getconfig(int skfd, int portal, char *ifname, int *pos, char *bp, struct net_stats_list *list)
{
	struct ifreq ifr;
	int metric, mtu, flags, family, has_ip, row = pos ? *pos : 0;
	struct sockaddr dstaddr, broadaddr, netmask, ifaddr, hwa;
	unsigned char *hwaddr;
        FILE *f;
        char addr6[40], devname[20];
        struct sockaddr_in6 sap;
        int plen, scope, dad_status, if_idx, fd, stats_valid;
        char addr6p[8][5], *w;
	int has_econet = 0, has_ddp = 0, has_ipx_bb = 0, has_ipx_sn = 0;
	int has_ipx_e3 = 0, has_ipx_e2 = 0;
        struct sockaddr ipxaddr_bb;
        struct sockaddr ipxaddr_sn;
        struct sockaddr ipxaddr_e3;
        struct sockaddr ipxaddr_e2;
        struct sockaddr ddpaddr;
        struct sockaddr ecaddr;
        struct ifmap map;
        unsigned long can_compress = 0, tx_queue_len, keepalive = 0,
		      outfill = 0;
        unsigned long long rx, tx, short_rx, short_tx;
        char rx_increment[5]="b";
        char tx_increment[5]="b";
        char display_buffer[1024];
        char format_buffer[1024];
        char cat_buffer[1024];

        struct user_net_device_stats *ifstats = search_nodes(ifname, list);
        if (ifstats)
           stats_valid = 1;

	strcpy(ifr.ifr_name, ifname);
	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) >= 0)
        {
	   hwa = ifr.ifr_hwaddr;
	   hwaddr = (unsigned char *)hwa.sa_data;
           family = ifr.ifr_hwaddr.sa_family;
        }
        else
        {
	   memset(&hwa, 0, sizeof(struct sockaddr));
	   hwaddr = (unsigned char *)hwa.sa_data;
           family = 0;
        }

	strcpy(ifr.ifr_name, ifname);
	if (ioctl(skfd, SIOCGIFFLAGS, &ifr) >= 0)
           flags = ifr.ifr_flags;
        else
           flags = 0;

	strcpy(ifr.ifr_name, ifname);
	if (ioctl(skfd, SIOCGIFADDR, &ifr) >= 0)
        {
           has_ip = 1;
           ifaddr = ifr.ifr_addr;
        }
        else
        {
	   memset(&ifaddr, 0, sizeof(struct sockaddr));
           has_ip = 0;
        }

	strcpy(ifr.ifr_name, ifname);
	if (ioctl(skfd, SIOCGIFMETRIC, &ifr) < 0) {
	   metric = 0;
	} else
	   metric = ifr.ifr_metric;

	strcpy(ifr.ifr_name, ifname);
	if (ioctl(skfd, SIOCGIFMTU, &ifr) < 0)
	   mtu = 0;
	else
	   mtu = ifr.ifr_mtu;

	strcpy(ifr.ifr_name, ifname);
	if (ioctl(skfd, SIOCGIFDSTADDR, &ifr) < 0) {
	   memset(&dstaddr, 0, sizeof(struct sockaddr));
	} else
	   dstaddr = ifr.ifr_dstaddr;

	strcpy(ifr.ifr_name, ifname);
	if (ioctl(skfd, SIOCGIFBRDADDR, &ifr) < 0) {
	   memset(&broadaddr, 0, sizeof(struct sockaddr));
	} else
	   broadaddr = ifr.ifr_broadaddr;

	strcpy(ifr.ifr_name, ifname);
	if (ioctl(skfd, SIOCGIFNETMASK, &ifr) < 0) {
	   memset(&netmask, 0, sizeof(struct sockaddr));
	} else
	   netmask = ifr.ifr_netmask;

        strcpy(ifr.ifr_name, ifname);
        if (ioctl(skfd, SIOCGIFTXQLEN, &ifr) < 0)
	   tx_queue_len = -1;
	else
	   tx_queue_len = ifr.ifr_qlen;

        if (family == ARPHRD_SLIP  || family == ARPHRD_CSLIP  ||
	    family == ARPHRD_SLIP6 || family == ARPHRD_CSLIP6 ||
	    family == ARPHRD_ADAPT)
        {
	    strcpy(ifr.ifr_name, ifname);
	    if (ioctl(skfd, SIOCGOUTFILL, &ifr) < 0)
	       outfill = 0;
	    else
	       outfill = (unsigned long) ifr.ifr_data;

	    strcpy(ifr.ifr_name, ifname);
	    if (ioctl(skfd, SIOCGKEEPALIVE, &ifr) < 0)
	       keepalive = 0;
	    else
	       keepalive = (unsigned long) ifr.ifr_data;
        }

        strcpy(ifr.ifr_name, ifname);
        if (ioctl(skfd, SIOCGIFMAP, &ifr) < 0)
	   memset(&map, 0, sizeof(struct ifmap));
        else
	   memcpy(&map, &ifr.ifr_map, sizeof(struct ifmap));

        display_buffer[0] = '\0';
	snprintf(format_buffer, sizeof(format_buffer), "%s Link encap:%s  ",
                ifname, get_arp_type(family));
        strcat(display_buffer, format_buffer);

        if (hwaddr)
        {
	  snprintf(format_buffer, sizeof(format_buffer),
                  "HWaddr: %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
	          hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3],
                  hwaddr[4], hwaddr[5]);
           strcat(display_buffer, format_buffer);
        }

	write_portal(portal, (const char *)display_buffer, row++, 2,
                        BRITEWHITE | BGBLUE);



        if (family == ARPHRD_CSLIP || family == ARPHRD_CSLIP6)
	   can_compress = 1;

        fd = socket(AF_APPLETALK, SOCK_DGRAM, 0);
        if (fd >= 0)
        {
	   strcpy(ifr.ifr_name, ifname);
	   if (ioctl(fd, SIOCGIFADDR, &ifr) == 0)
           {
	       ddpaddr = ifr.ifr_addr;
	       has_ddp = 1;
	   }
           close(fd);
        }

        fd = socket(AF_IPX, SOCK_DGRAM, 0);
        if (fd >= 0)
        {
	   strcpy(ifr.ifr_name, ifname);
	   if (!ipx_getaddr(fd, IPX_FRAME_ETHERII, &ifr))
           {
	      has_ipx_bb = 1;
	      ipxaddr_bb = ifr.ifr_addr;
	   }
	   strcpy(ifr.ifr_name, ifname);
	   if (!ipx_getaddr(fd, IPX_FRAME_SNAP, &ifr))
           {
	      has_ipx_sn = 1;
	      ipxaddr_sn = ifr.ifr_addr;
	   }
	   strcpy(ifr.ifr_name, ifname);
	   if (!ipx_getaddr(fd, IPX_FRAME_8023, &ifr))
           {
	      has_ipx_e3 = 1;
	      ipxaddr_e3 = ifr.ifr_addr;
	   }
	   strcpy(ifr.ifr_name, ifname);
	   if (!ipx_getaddr(fd, IPX_FRAME_8022, &ifr))
           {
	      has_ipx_e2 = 1;
	      ipxaddr_e2 = ifr.ifr_addr;
	   }
           close(fd);
        }

        fd = socket(AF_ECONET, SOCK_DGRAM, 0);
        if (fd >= 0)
        {
	   strcpy(ifr.ifr_name, ifname);
	   if (ioctl(fd, SIOCGIFADDR, &ifr) == 0)
           {
	      ecaddr = ifr.ifr_addr;
	      has_econet = 1;
	   }
           close(fd);
        }

	if (has_ipx_bb)
        {
	   snprintf(display_buffer, sizeof(display_buffer), ("IPX/Ethernet II addr:%s"),
		   IPX_sprint(&ipxaddr_bb, 1));
           write_portal(portal, (const char *)display_buffer, row++, 2,
                        BRITEWHITE | BGBLUE);
        }

	if (has_ipx_sn)
        {
	   snprintf(display_buffer, sizeof(display_buffer), ("IPX/Ethernet SNAP addr:%s"),
		   IPX_sprint(&ipxaddr_sn, 1));
           write_portal(portal, (const char *)display_buffer, row++, 2,
                        BRITEWHITE | BGBLUE);
        }

	if (has_ipx_e2)
        {
	   snprintf(display_buffer, sizeof(display_buffer), ("IPX/Ethernet 802.2 addr:%s"),
		   IPX_sprint(&ipxaddr_e2, 1));
           write_portal(portal, (const char *)display_buffer, row++, 2,
                        BRITEWHITE | BGBLUE);
        }

	if (has_ipx_e3)
        {
	   snprintf(display_buffer, sizeof(display_buffer), ("IPX/Ethernet 802.3 addr:%s"),
		   IPX_sprint(&ipxaddr_e3, 1));
           write_portal(portal, (const char *)display_buffer, row++, 2,
                        BRITEWHITE | BGBLUE);
        }

	if (has_ddp)
        {
	   snprintf(display_buffer, sizeof(display_buffer), ("EtherTalk Phase 2 addr:%s"),
                   ddp_sprint(&ddpaddr, 1));
           write_portal(portal, (const char *)display_buffer, row++, 2,
                        BRITEWHITE | BGBLUE);
        }

	if (has_econet)
        {
	   snprintf(display_buffer, sizeof(display_buffer), ("econet addr:%s"),
                   ec_sprint(&ecaddr, 1));
           write_portal(portal, (const char *)display_buffer, row++, 2,
                        BRITEWHITE | BGBLUE);
        }

        display_buffer[0] = '\0';
        if (flags == 0)
	  strcat(display_buffer, ("[NO FLAGS] "));
        if (flags & IFF_UP)
	  strcat(display_buffer, ("UP "));
        if (flags & IFF_BROADCAST)
	  strcat(display_buffer, ("BROADCAST "));
        if (flags & IFF_DEBUG)
	  strcat(display_buffer, ("DEBUG "));
        if (flags & IFF_LOOPBACK)
	  strcat(display_buffer, ("LOOPBACK "));
        if (flags & IFF_POINTOPOINT)
	  strcat(display_buffer, ("POINTOPOINT "));
        if (flags & IFF_NOTRAILERS)
	  strcat(display_buffer, ("NOTRAILERS "));
        if (flags & IFF_RUNNING)
	  strcat(display_buffer, ("RUNNING "));
        if (flags & IFF_NOARP)
	  strcat(display_buffer, ("NOARP "));
        if (flags & IFF_PROMISC)
	  strcat(display_buffer, ("PROMISC "));
        if (flags & IFF_ALLMULTI)
	  strcat(display_buffer, ("ALLMULTI "));
        if (flags & IFF_SLAVE)
	  strcat(display_buffer, ("SLAVE "));
        if (flags & IFF_MASTER)
	  strcat(display_buffer, ("MASTER "));
        if (flags & IFF_MULTICAST)
	  strcat(display_buffer, ("MULTICAST "));
        if (flags & IFF_DYNAMIC)
	  strcat(display_buffer, ("DYNAMIC "));

        snprintf(format_buffer, sizeof(format_buffer),
		 " MTU:%u  Metric:%u",
		 mtu, metric ? metric : 1);
	strcat(display_buffer, format_buffer);

        if (outfill || keepalive)
        {
           snprintf(format_buffer, sizeof(format_buffer),
		    "  Outfill:%ld  Keepalive:%ld",
		    outfill, keepalive);
	   strcat(display_buffer, format_buffer);
        }
        write_portal(portal, (const char *)display_buffer, row++, 2,
                    BRITEWHITE | BGBLUE);

        if (has_ip)
        {
           display_buffer[0] = '\0';
           snprintf(format_buffer, sizeof(format_buffer),
		    "inet addr:%u.%u.%u.%u  ",
                  clip(ifaddr.sa_data[2]), clip(ifaddr.sa_data[3]),
                  clip(ifaddr.sa_data[4]), clip(ifaddr.sa_data[5]));
	   strcat(display_buffer, format_buffer);

	   if (flags & IFF_POINTOPOINT)
           {
              snprintf(format_buffer, sizeof(format_buffer),
		       "P-t-P:%u.%u.%u.%u  ",
                  clip(dstaddr.sa_data[2]), clip(dstaddr.sa_data[3]),
                  clip(dstaddr.sa_data[4]), clip(dstaddr.sa_data[5]));
	      strcat(display_buffer, format_buffer);
	   }

	   if (flags & IFF_BROADCAST)
           {
              snprintf(format_buffer, sizeof(format_buffer),
		       "Bcast:%u.%u.%u.%u  ",
                  clip(broadaddr.sa_data[2]), clip(broadaddr.sa_data[3]),
                  clip(broadaddr.sa_data[4]), clip(broadaddr.sa_data[5]));
	      strcat(display_buffer, format_buffer);
	   }
           snprintf(format_buffer, sizeof(format_buffer),
		    "Mask:%u.%u.%u.%u",
                  clip(netmask.sa_data[2]), clip(netmask.sa_data[3]),
                  clip(netmask.sa_data[4]), clip(netmask.sa_data[5]));
	   strcat(display_buffer, format_buffer);

           write_portal(portal, (const char *)display_buffer, row++, 2,
                        BRITEWHITE | BGBLUE);
        }

        if ((f = fopen("/proc/net/if_inet6", "r")) != NULL)
        {
	   while (fscanf(f, "%4s%4s%4s%4s%4s%4s%4s%4s %02x %02x"
                             " %02x %02x %20s\n",
		      addr6p[0], addr6p[1], addr6p[2], addr6p[3],
		      addr6p[4], addr6p[5], addr6p[6], addr6p[7],
		  &if_idx, &plen, &scope, &dad_status, devname) != EOF)
           {
	      if (!strcmp(devname, ifname))
              {
                 display_buffer[0] = '\0';
	         snprintf(addr6, sizeof(addr6), "%s:%s:%s:%s:%s:%s:%s:%s",
			 addr6p[0], addr6p[1], addr6p[2], addr6p[3],
			 addr6p[4], addr6p[5], addr6p[6], addr6p[7]);

		 INET6_input(1, addr6, (struct sockaddr *) &sap);
		 snprintf(format_buffer, sizeof(format_buffer),
			  ("inet6 addr: %s/%d"),
		       INET6_sprint((struct sockaddr *) &sap, 1), plen);
	         strcat(display_buffer, format_buffer);

		 snprintf(format_buffer, sizeof(format_buffer), (" Scope:"));
	         strcat(display_buffer, format_buffer);

		 switch (scope)
                 {
		     case 0:
		        strcat(display_buffer, ("Global"));
		        break;

		     case IPV6_ADDR_LINKLOCAL:
		        strcat(display_buffer, ("Link"));
		        break;

		     case IPV6_ADDR_SITELOCAL:
		        strcat(display_buffer, ("Site"));
		        break;

		     case IPV6_ADDR_COMPATv4:
		        strcat(display_buffer, ("Compat"));
		        break;

		     case IPV6_ADDR_LOOPBACK:
		        strcat(display_buffer, ("Host"));
		        break;

		     default:
		        strcat(display_buffer, ("Unknown"));
		  }
                  write_portal(portal, (const char *)display_buffer, row++, 2,
                               BRITEWHITE | BGBLUE);
	      }
	   }
	   fclose(f);
        }

        if (stats_valid)
        {
	   w = comma_snprintf(format_buffer, sizeof(format_buffer), "%llu", ifstats->rx_packets);
           snprintf(display_buffer, sizeof(display_buffer), "RX packets   : %s", w);
           write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);

	   w = comma_snprintf(format_buffer, sizeof(format_buffer), "%llu", ifstats->p_rx_packets ? ifstats->rx_packets - ifstats->p_rx_packets : 0);
           snprintf(display_buffer, sizeof(display_buffer), "RX pkts/sec  : %s", w);
           write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);

	   w = comma_snprintf(format_buffer, sizeof(format_buffer), "%lu", ifstats->rx_errors);
           snprintf(display_buffer, sizeof(display_buffer), "RX errors    : %s", w);
           write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);

	   w = comma_snprintf(format_buffer, sizeof(format_buffer), "%lu", ifstats->rx_dropped);
           snprintf(display_buffer, sizeof(display_buffer), "RX dropped   : %s", w);
           write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);

	   w = comma_snprintf(format_buffer, sizeof(format_buffer), "%lu", ifstats->rx_fifo_errors);
           snprintf(display_buffer, sizeof(display_buffer), "RX overruns  : %s", w);
           write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);

	   w = comma_snprintf(format_buffer, sizeof(format_buffer), "%lu",ifstats->rx_frame_errors);
           snprintf(display_buffer, sizeof(display_buffer), "RX frame err : %s", w);
           write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);

	   rx = ifstats->rx_bytes;
	   tx = ifstats->tx_bytes;
	   short_rx = rx * 10;
	   short_tx = tx * 10;

	   if (rx > 1000000000000000000)
           {
              short_rx /= 1000000000000000000;
              strcpy(rx_increment, "Eb");
           }
	   else
	   if (rx > 1000000000000000)
           {
              short_rx /= 1000000000000000;
              strcpy(rx_increment, "Pb");
           }
	   else
	   if (rx > 1000000000000)
           {
              short_rx /= 1000000000000;
              strcpy(rx_increment, "Tb");
           }
	   else
	   if (rx > 1000000000)
           {
              short_rx /= 1000000000;
              strcpy(rx_increment, "Gb");
           }
	   else
	   if (rx > 1000000)
           {
              short_rx /= 1000000;
              strcpy(rx_increment, "Mb");
           }
	   else
           if (rx > 1000)
           {
              short_rx /= 1000;
              strcpy(rx_increment, "Kb");
           }

	   if (tx > 1000000000000000000)
           {
              short_tx /= 1000000000000000000;
              strcpy(tx_increment, "Eb");
           }
	   else
	   if (tx > 1000000000000000)
           {
              short_tx /= 1000000000000000;
              strcpy(tx_increment, "Pb");
           }
	   else
	   if (tx > 1000000000000)
           {
              short_tx /= 1000000000000;
              strcpy(tx_increment, "Tb");
           }
	   else
	   if (tx > 1000000000)
           {
              short_tx /= 1000000000;
              strcpy(tx_increment, "Gb");
           }
	   else
	   if (tx > 1000000)
           {
              short_tx /= 1000000;
              strcpy(tx_increment, "Mb");
           }
	   else
           if (tx > 1000)
           {
              short_tx /= 1000;
              strcpy(tx_increment, "Kb");
           }

	   w = comma_snprintf(format_buffer, sizeof(format_buffer), "%llu", ifstats->tx_packets);
           snprintf(display_buffer, sizeof(display_buffer), "TX packets   : %s", w);
           write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);

	   w = comma_snprintf(format_buffer, sizeof(format_buffer), "%llu", ifstats->p_tx_packets ? ifstats->tx_packets - ifstats->p_tx_packets : 0);
           snprintf(display_buffer, sizeof(display_buffer), "TX pkts/sec  : %s", w);
           write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);

	   w = comma_snprintf(format_buffer, sizeof(format_buffer), "%lu", ifstats->tx_errors);
           snprintf(display_buffer, sizeof(display_buffer), "TX errors    : %s", w);
           write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);

	   w = comma_snprintf(format_buffer, sizeof(format_buffer), "%lu", ifstats->tx_dropped);
           snprintf(display_buffer, sizeof(display_buffer), "TX dropped   : %s", w);
           write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);

	   w = comma_snprintf(format_buffer, sizeof(format_buffer), "%lu", ifstats->tx_fifo_errors);
           snprintf(display_buffer, sizeof(display_buffer), "TX overruns  : %s", w);
           write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);

	   w = comma_snprintf(format_buffer, sizeof(format_buffer), "%lu", ifstats->tx_carrier_errors);
           snprintf(display_buffer, sizeof(display_buffer), "TX carrier   : %s", w);
           write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);

	   w = comma_snprintf(format_buffer, sizeof(format_buffer), "%lu", ifstats->collisions);
           snprintf(display_buffer, sizeof(display_buffer), "collisions   : %s", w);
           write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);

	   if (can_compress)
           {
	      w = comma_snprintf(format_buffer, sizeof(format_buffer), "%lu", ifstats->tx_compressed);
              snprintf(display_buffer, sizeof(display_buffer), "compressed   : %s", w);
              write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);
           }

	   if (tx_queue_len != (unsigned long)-1)
           {
	      w = comma_snprintf(format_buffer, sizeof(format_buffer), "%ld", tx_queue_len);
              snprintf(display_buffer, sizeof(display_buffer), "txqueuelen   : %s", w);
              write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);
           }

	   w = comma_snprintf(format_buffer, sizeof(format_buffer), "%llu", ifstats->p_rx_bytes ? ifstats->rx_bytes - ifstats->p_rx_bytes : 0);
           snprintf(display_buffer, sizeof(display_buffer), "RX bytes/sec : %s", w);
	   write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);

           w = comma_snprintf(format_buffer, sizeof(format_buffer), "%llu", ifstats->p_tx_bytes ? ifstats->tx_bytes - ifstats->p_tx_bytes : 0);
           snprintf(display_buffer, sizeof(display_buffer), "TX bytes/sec : %s", w);
	   write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);

	   w = comma_snprintf(format_buffer, sizeof(format_buffer), "%llu", rx);
           snprintf(display_buffer, sizeof(display_buffer), "RX bytes     : %s", w);
	   w = comma_snprintf(format_buffer, sizeof(format_buffer), "%llu", (unsigned long long)(short_rx / 10));
           snprintf(cat_buffer, sizeof(cat_buffer), " (%s.%llu %s) ", w, (unsigned long long)(short_rx % 10), rx_increment);
	   strcat(display_buffer, cat_buffer);
	   write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);

	   w = comma_snprintf(format_buffer, sizeof(format_buffer), "%llu", tx);
           snprintf(display_buffer, sizeof(display_buffer), "TX bytes     : %s", w);
           w = comma_snprintf(format_buffer, sizeof(format_buffer), "%llu", (unsigned long long)(short_tx / 10));
           snprintf(cat_buffer, sizeof(cat_buffer), " (%s.%llu %s) ", w, (unsigned long long)(short_tx % 10), tx_increment);
	   strcat(display_buffer, cat_buffer);
           write_portal_cleol(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);
        }

        if ((map.irq || map.mem_start || map.dma || map.base_addr))
        {
           display_buffer[0] = '\0';
	   if (map.irq)
           {
	      snprintf(format_buffer, sizeof(format_buffer), ("Interrupt:%d "), map.irq);
	      strcat(display_buffer, format_buffer);
           }

	   if (map.base_addr >= 0x100)
           {
	      snprintf(format_buffer, sizeof(format_buffer), ("Base address:0x%x "), map.base_addr);
	      strcat(display_buffer, format_buffer);
           }

	   if (map.mem_start)
           {
	      snprintf(format_buffer, sizeof(format_buffer), ("Memory:%lx-%lx "), map.mem_start, map.mem_end);
	      strcat(display_buffer, format_buffer);
           }

	   if (map.dma)
           {
	      snprintf(format_buffer, sizeof(format_buffer), ("DMA chan:%x "), map.dma);
	      strcat(display_buffer, format_buffer);
           }
           write_portal(portal, (const char *)display_buffer, row++, 2, BRITEWHITE | BGBLUE);
        }
        write_portal(portal, (const char *)" ", row++, 2, BRITEWHITE | BGBLUE);
        if (pos)
           *pos = row;

	return 0;
}

char *get_name(char *name, char *p)
{
    while (isspace(*p))
	p++;
    while (*p) {
	if (isspace(*p))
	    break;
	if (*p == ':')
        {
	    // could be an alias
	    char *dot = p, *dotname = name;

	    *name++ = *p++;

	    while (isdigit(*p))
		*name++ = *p++;

	    if (*p != ':')
            {
	        // it wasn't, backup
		p = dot;
		name = dotname;
	    }

	    if (*p == '\0')
		return NULL;

	    p++;
	    break;
	}
	*name++ = *p++;
    }
    *name++ = '\0';
    return p;
}

int get_network_totals(struct net_stats_list *list)
{
    FILE *fp;
    char buf[1024];
    int err;

    if (!list || !list->current || !list->previous) 
	return -1;

    fp = fopen("/proc/net/dev", "r");
    if (!fp)
       return -1;

    fgets(buf, sizeof buf, fp);	 // eat line
    fgets(buf, sizeof buf, fp);
    if (strstr(buf, "compressed"))
       pnv = 3;
    else
    if (strstr(buf, "bytes"))
       pnv = 2;
    else
       pnv = 1;
    list->previous->rx_bytes = list->current->rx_bytes;
    list->previous->rx_packets = list->current->rx_packets;
    list->previous->tx_bytes = list->current->tx_bytes;
    list->previous->tx_packets = list->current->tx_packets;
    list->current->rx_bytes = 0;
    list->current->rx_packets = 0;
    list->current->tx_bytes = 0;
    list->current->tx_packets = 0;
    err = 0;
    while (fgets(buf, sizeof buf, fp))
    {
	char name[IFNAMSIZ+1], *s;

	s = get_name(name, buf);
        if (s) {
           struct user_net_device_stats *stats;

	   stats = search_nodes(name, list);
	   if (stats) {	
              stats->p_rx_bytes = stats->rx_bytes;
              stats->p_tx_bytes = stats->tx_bytes;
              stats->p_rx_packets = stats->rx_packets;
              stats->p_tx_packets = stats->tx_packets;
	      get_dev_fields(s, stats);
              list->current->rx_bytes += stats->rx_bytes;
              list->current->tx_bytes += stats->tx_bytes;
              list->current->rx_packets += stats->rx_packets;
              list->current->tx_packets += stats->tx_packets;
           }
        }
    }
    fclose(fp);
    return err;
}

int display_network_summary(int portal, char *ifname, struct net_stats_list *list)
{
    FILE *fp;
    char buf[1024];
    int err, pos = 0, skfd;
    char nbuf[1024], *w;

    get_network_totals(list);

    snprintf(buf, sizeof(buf), "General Network Statistics");
    write_portal_cleol(portal, (const char *)buf, pos++, 2, BRITEWHITE | BGBLUE);

    int y;
    char ch = get_horizontal_frame(portal);
    if (ch) {
       for (y=2; y < (get_screen_cols() - 6); y++) {
          write_portal_char(portal, (BYTE)ch, pos, y, BRITEWHITE | BGBLUE);
       }
       pos++;
    }
    else
       write_portal_line(portal, pos++, BRITEWHITE | BGBLUE);

    w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", list->previous->rx_bytes ? list->current->rx_bytes - list->previous->rx_bytes : 0, 19);
    snprintf(buf, sizeof(buf), "Network Receives/Second   :   %22s", w);
    write_portal_cleol(portal, (const char *)buf, pos++, 2, BRITEWHITE | BGBLUE);

    w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", list->previous->tx_bytes ? list->current->tx_bytes - list->previous->tx_bytes : 0, 19);
    snprintf(buf, sizeof(buf), "Network Transmits/Second  :   %22s", w);
    write_portal_cleol(portal, (const char *)buf, pos++, 2, BRITEWHITE | BGBLUE);

    w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", list->previous->rx_packets ? list->current->rx_packets - list->previous->rx_packets : 0, 19);
    snprintf(buf, sizeof(buf), "Network Receive Pkts/Sec  :   %22s", w);
    write_portal_cleol(portal, (const char *)buf, pos++, 2, BRITEWHITE | BGBLUE);

    w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", list->previous->tx_packets ? list->current->tx_packets - list->previous->tx_packets : 0, 19);
    snprintf(buf, sizeof(buf), "Network Transmit Pkts/Sec :   %22s", w);
    write_portal_cleol(portal, (const char *)buf, pos++, 2, BRITEWHITE | BGBLUE);

    w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", list->current->rx_bytes, 19);
    snprintf(buf, sizeof(buf), "Total Receive Bytes       :   %22s", w);
    write_portal_cleol(portal, (const char *)buf, pos++, 2, BRITEWHITE | BGBLUE);

    w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", list->current->tx_bytes, 19);
    snprintf(buf, sizeof(buf), "Total Transmit Bytes      :   %22s", w);
    write_portal_cleol(portal, (const char *)buf, pos++, 2, BRITEWHITE | BGBLUE);

    w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", list->current->rx_packets, 19);
    snprintf(buf, sizeof(buf), "Total Receive Packets     :   %22s", w);
    write_portal_cleol(portal, (const char *)buf, pos++, 2, BRITEWHITE | BGBLUE);

    w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", list->current->tx_packets, 19);
    snprintf(buf, sizeof(buf), "Total Transmit Packets    :   %22s", w);
    write_portal_cleol(portal, (const char *)buf, pos++, 2, BRITEWHITE | BGBLUE);
    pos++;

    if (ch) {
       for (y=2; y < (get_screen_cols() - 6); y++) {
          write_portal_char(portal, (BYTE)ch, pos, y, BRITEWHITE | BGBLUE);
       }
       pos++;
    }
    else
       write_portal_line(portal, pos++, BRITEWHITE | BGBLUE);

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (skfd < 0)
       return skfd;

    fp = fopen("/proc/net/dev", "r");
    if (!fp)
    {
       close(skfd);
       return -1;
    }

    fgets(buf, sizeof buf, fp);	 // eat line
    fgets(buf, sizeof buf, fp);

    if (strstr(buf, "compressed"))
       pnv = 3;
    else
    if (strstr(buf, "bytes"))
       pnv = 2;
    else
       pnv = 1;


    err = 0;
    while (fgets(buf, sizeof buf, fp))
    {
	char name[IFNAMSIZ+1], *s;
        int y;
        char ch = get_horizontal_frame(portal);

	s = get_name(name, buf);
        if (!ifname)
        {
           if_getconfig(skfd, portal, name, &pos, s, list);
           if (ch) {
 	      for (y=2; y < (get_screen_cols() - 6); y++) {
                 write_portal_char(portal, (BYTE)ch, pos, y, BRITEWHITE | BGBLUE);
              }
              pos++;
           }
	   else
              write_portal_line(portal, pos++, BRITEWHITE | BGBLUE);
        }
        else
        if (!strcasecmp(ifname, name))
        {
           if_getconfig(skfd, portal, name, &pos, s, list);
           if (ch) {
 	      for (y=2; y < (get_screen_cols() - 6); y++) {
                 write_portal_char(portal, (BYTE)ch, pos, y, BRITEWHITE | BGBLUE);
              }
              pos++;
           }
	   else
              write_portal_line(portal, pos++, BRITEWHITE | BGBLUE);
        }
    }
    fclose(fp);
    close(skfd);
    return err;
}

void *network_routine(void *p)
{
   NP *np = (NP *)p;
   int portal = np ? np->portal : 0;
   char *ifname = np ? np->ifname : NULL;
   int state;

   while (networkactive && p && np)
   {
      pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
      display_network_summary(portal, ifname, &np->list);
      update_static_portal(portal);
      pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &state);
      sleep(1);
      if (!get_sleep_count(portal))
         clear_portal_focus(portal);
   }
   return NULL;
}

void *network_summary_routine(void *p)
{
   NP *np = (NP *)p;
   int portal = np ? np->portal : 0;
   int state;

   while (netsumactive && p && np)
   {
       pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
       display_network_summary(portal, NULL, &np->list);
       update_static_portal(portal);
       pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &state);
       sleep(1);
       if (!get_sleep_count(portal))
          clear_portal_focus(portal);
   }
   return NULL;
}

int scan_diskstats(PSTATE *p)
{
	register int i;
	char line[1024];
	char *s;
	FILE *f;
	
	if (NULL != (f = fopen("/proc/diskstats", "r")))
	{
		p->n_part = 0;
       		while (!feof(f))
		{
			s = fgets(line, 1024, f);
			if (s)
			{
				p->p[p->n_part].p_read = p->p[p->n_part].sectors_read;
				p->p[p->n_part].p_written = p->p[p->n_part].sectors_written;
				p->p[p->n_part].p_iotime = p->p[p->n_part].io_time;
				p->p[p->n_part].p_read_time = p->p[p->n_part].read_time;
				p->p[p->n_part].p_write_time = p->p[p->n_part].write_time;
				p->p[p->n_part].p_io_active = p->p[p->n_part].io_active;
				p->p[p->n_part].p_io_weight = p->p[p->n_part].io_weight;

				if (sscanf(line, "%d %d %255s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
					&p->p[p->n_part].major,
					&p->p[p->n_part].minor,
					&p->p[p->n_part].device_name[0],
					&p->p[p->n_part].reads,
					&p->p[p->n_part].reads_merged,
					&p->p[p->n_part].sectors_read,
					&p->p[p->n_part].read_time,
					&p->p[p->n_part].writes,
					&p->p[p->n_part].writes_merged,
					&p->p[p->n_part].sectors_written,
					&p->p[p->n_part].write_time,
					&p->p[p->n_part].io_active,
					&p->p[p->n_part].io_time,
					&p->p[p->n_part].io_weight) != 14)
				{
					fclose(f);
					return p->n_part;
				}
				if ((p->n_part + 1) < MAX_PARTITIONS)
					p->n_part++;
			}
		}
		fclose(f);
	}

	p->total_reads = 0;
	p->total_reads_merged = 0;
	p->total_sectors_read = 0;
	p->total_read_time = 0;
	p->total_writes = 0;
	p->total_writes_merged = 0;
	p->total_sectors_written = 0;
	p->total_write_time = 0;
	p->total_io_active = 0;
	p->total_io_time = 0;
	p->total_io_weight = 0;
	p->total_p_read = 0;
	p->total_p_written = 0;
	p->total_p_iotime = 0;
	p->total_p_read_time = 0;
	p->total_p_write_time = 0;
	p->total_p_io_active = 0;
	p->total_p_io_weight = 0;

	for (i=0; i < p->n_part; i++) {
		if (detect_disk(p->p[i].major, p->p[i].minor)) {
			p->total_reads += p->p[i].reads;
			p->total_reads_merged += p->p[i].reads_merged;
			p->total_sectors_read += p->p[i].sectors_read;
			p->total_read_time += p->p[i].read_time;
			p->total_writes += p->p[i].writes;
			p->total_writes_merged += p->p[i].writes_merged;
			p->total_sectors_written += p->p[i].sectors_written;
			p->total_write_time += p->p[i].write_time;
			p->total_io_active += p->p[i].io_active;
			p->total_io_time += p->p[i].io_time;
			p->total_io_weight += p->p[i].io_weight;
			p->total_p_read += p->p[i].p_read;
			p->total_p_written += p->p[i].p_written;
			p->total_p_iotime += p->p[i].p_iotime;
			p->total_p_read_time += p->p[i].p_read_time;
			p->total_p_write_time += p->p[i].p_write_time;
			p->total_p_io_active += p->p[i].p_io_active;
			p->total_p_io_weight += p->p[i].p_io_weight;
		}
	}
	return p->n_part;
}

char *get_cpu_load(STATE *st, int cpu, char *outbuf, int outlen, int flags)
{
    static char line[100];
    unsigned long long p_usr = 0, p_nice = 0, p_sys  = 0, p_idle = 0, load = 0, len;
    unsigned long long p_io = 0, p_irq = 0, p_sirq = 0;
    FILE *f;
    char src[100] = "\0", *s;

    if (flags) {
	    snprintf(src, 100, "cpu");
	    len = strlen(src);

	    if (NULL != (f = fopen("/proc/stat", "r")))
	    {
        	    s = fgets(line, 98, f);
	            if (s && !strncasecmp(src, line, len))
		    {
			p_usr  = st->total_usr;
	                p_nice = st->total_nice;
	                p_sys  = st->total_sys;
	                p_idle = st->total_idle;
	                p_io = st->total_io;
	                p_irq = st->total_irq;
	                p_sirq = st->total_sirq;

        	        if (sscanf(&line[len + 1], "%llu %llu %llu %llu %llu %llu %llu",
				   &(st->total_usr), &(st->total_nice),
				   &(st->total_sys), &(st->total_idle),
				   &(st->total_io), &(st->total_irq),
				   &(st->total_sirq)) == 7)
			{
			    // calculate total cycles
                	    load = st->total_usr - p_usr + st->total_nice - p_nice
				    + st->total_sys - p_sys + st->total_idle - p_idle;

			    // prevent divide by zero if result is 0
			    if (!load)
        	                load = 1;

			    // subtract idle cycles from load and mulitply * 100
			    // to express as percentage
			    load = (load - (st->total_idle - p_idle)) * 100 / load;
	                }
	                else
			{
		            fclose(f);
                	    return NULL;
			}
	        }
		fclose(f);
	    }	

	    if (p_usr) {
	       snprintf(outbuf, outlen, "%%Cpus  %3llu%% %3llu%% us, %3llu%% sy, %3llu%% ni, %3llu%% id, %3llu%% wa, %3llu%% si, %3llu%% st",
			load,
			st->cpus ? (st->total_usr - p_usr) / st->cpus : 0,
			st->cpus ? (st->total_sys - p_sys) / st->cpus : 0,
			st->cpus ? (st->total_nice - p_nice) / st->cpus : 0,
			st->cpus ? (st->total_idle - p_idle) / st->cpus : 0,
			st->cpus ? (st->total_io - p_io) / st->cpus : 0,
			st->cpus ? (st->total_irq - p_irq) / st->cpus : 0,
			st->cpus ? (st->total_sirq - p_sirq) / st->cpus : 0);
	    }
	    else {
		snprintf(outbuf, outlen, "%%Cpus  %3d%% %3d%% us, %3d%% sy, %3d%% ni, %3d%% id, %3d%% wa, %3d%% si, %3d%% st",
			0, 0, 0, 0, 0, 0, 0, 0);
	    }
	    return outbuf;
    }

    if (cpu > st->cpus)
        return NULL;

    if (cpu > MAX_CPUS)
        return NULL;

    // convert cpu num to ascii text number
    // and null terminate
    snprintf(src, 100, "cpu%d", cpu);
    len = strlen(src);

    if (NULL != (f = fopen("/proc/stat", "r")))
    {
        while (!feof(f) && !load)
	{
            s = fgets(line, 98, f);
            if (s && !strncasecmp(src, line, len))
	    {
		p_usr  = st->usr[cpu];
                p_nice = st->nice[cpu];
                p_sys  = st->sys [cpu];
                p_idle = st->idle[cpu];
                p_io = st->io[cpu];
                p_irq = st->irq[cpu];
                p_sirq = st->sirq[cpu];

                if (sscanf(&line[len + 1], "%llu %llu %llu %llu %llu %llu %llu",
			   &(st->usr[cpu]), &(st->nice[cpu]),
			   &(st->sys[cpu]), &(st->idle[cpu]),
			   &(st->io[cpu]), &(st->irq[cpu]),
			   &(st->sirq[cpu])) == 7)
		{
		    // calculate total cycles
                    load = st->usr[cpu] - p_usr + st->nice[cpu] - p_nice
			    + st->sys[cpu] - p_sys + st->idle[cpu] - p_idle;

		    // prevent divide by zero if result is 0
		    if (!load)
                        load = 1;

		    // subtract idle cycles from load and mulitply * 100
		    // to express as percentage
		    load = (load - (st->idle[cpu] - p_idle)) * 100 / load;
                    break;
                }
                else
		{
	            fclose(f);
                    return NULL;
		}
            }
        }
	fclose(f);
    }
	
    if (p_usr) {
       snprintf(outbuf, outlen, "%%Cpu%02d %3llu%% %3llu%% us, %3llu%% sy, %3llu%% ni, %3llu%% id, %3llu%% wa, %3llu%% si, %3llu%% st",
   	    cpu, load,
	 st->usr[cpu] - p_usr,
	 st->sys[cpu] - p_sys,
	 st->nice[cpu] - p_nice,
	 st->idle[cpu] - p_idle,
	 st->io[cpu] - p_io,
	 st->irq[cpu] - p_irq,
	 st->sirq[cpu] - p_sirq);
    }
    else {
       snprintf(outbuf, outlen, "%%Cpu%02d %3d%% %3d%% us, %3d%% sy, %3d%% ni, %3d%% id, %3d%% wa, %3d%% si, %3d%% st",
   	    cpu, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    return outbuf;
}

unsigned long get_uptime(void)
{
	char *s, line[100];;
	FILE *fp;
	float up = 0, idle = 0;

	fp = fopen("/proc/uptime", "r");
	if (fp)	{
		while (!feof(fp)) {
			s = fgets(line, 98, fp);
			if (s)	{
				if (sscanf(line, "%f %f", &up, &idle) != 2) {
					return 0;
				}
				break;
			}
		}
		fclose(fp);
	}
	return (unsigned long) up;

}

struct mem_stats_list {
	unsigned long long mem_total;
	unsigned long long mem_free;
	unsigned long long mem_allocated;
	unsigned long long mem_available;
	unsigned long long swap_total;
	unsigned long long swap_free;
	unsigned long long swap_allocated;
	unsigned long long buffers;
};

struct mem_stats_list *get_mem_stats(struct mem_stats_list *ml)
{
	char *s, line[100], name[1024], factor[100];
	unsigned long long value;
	FILE *fp;

	fp = fopen("/proc/meminfo", "r");
	if (fp)	{
		while (!feof(fp)) {
			s = fgets(line, 98, fp);
            		if (s) {
				if (sscanf(s, "%s %llu %s", name, &value, factor) == 3) {
					if (!strcasecmp(name, "MemTotal:")) {
						ml->mem_total = value;
					}
					else if (!strcasecmp(name, "MemFree:")) {
						ml->mem_free = value;
					}
					else if (!strcasecmp(name, "SwapTotal:")) {
						ml->swap_total = value;
					}
					else if (!strcasecmp(name, "SwapFree:")) {
						ml->swap_free = value;
					}
					else if (!strcasecmp(name, "Buffers:")) {
						ml->buffers = value;
					}
					else if (!strcasecmp(name, "MemAvailable:")) {
						ml->mem_available = value;
					}
				}
			}
		}
		fclose(fp);

		if (ml->mem_total > ml->mem_free)
			ml->mem_allocated = ml->mem_total - ml->mem_free;
		if (ml->swap_total > ml->swap_free)
			ml->swap_allocated = ml->swap_total - ml->swap_free;
	}
	return ml;
}

unsigned long years;
unsigned long months;
unsigned long days;
unsigned long hours;
unsigned long minutes;
unsigned long seconds;
unsigned long uptime;

void output_uptime(unsigned long long uptime) 
{
	years    = uptime / 60 / 60 / 24 / 30 / 12;
	months   = uptime / 60 / 60 / 24 / 30 % 12;
	days     = uptime / 60 / 60 / 24 % 30;
	hours    = uptime / 60 / 60 % 24;
	minutes  = uptime / 60 % 60;
	seconds  = uptime % 60;
}

#define STATS_MEM_NAME "/leafstats"
#define SEM_MUTEX_NAME "/leafmutex"

#define SHORT_FORMAT  1
#define LONG_FORMAT   2

int sem_lock(sem_t *mutex_sem)
{
	if (!mutex_sem)
		return -EINVAL;
	if (sem_wait(mutex_sem) == -1)
		return -EINTR;
	return 0;
}

int sem_unlock(sem_t *mutex_sem)
{
	if (!mutex_sem)
		return -EINVAL;
	if (sem_post(mutex_sem) == -1)
		return -EINTR;
	return 0;
}

int display_leaf_summary(int portal, STATE *st, PSTATE *pr, LCTX *ctx, struct net_stats_list *list, int flags)
{
	GLOBAL *stats_ptr = NULL;
	sem_t *mutex_sem = NULL;
	int stats_shm, row, n;
	char buf[8192];
	char nbuf[1024], *w;
	char outbuf[1024], *s;
	float util;
	
	if (!ctx || !list || !list->current || !list->previous) {
       	   write_portal_cleol(portal, "leafmon: context pointers not set in display_leaf_summary", 0, 2, BRITEWHITE | BGBLUE);
	   return 0;
	}
	
        st->cpus = get_processors();
        if (st->cpus > MAX_CPUS)
  	   st->cpus = MAX_CPUS;

	row = 0;
	uptime = get_uptime();
	output_uptime(uptime); 

	snprintf(buf, sizeof(buf), "Server Uptime:   ");
	if (years) {
		snprintf(outbuf, sizeof(buf), "%lu Years ", years);
		strcat(buf, outbuf);
	}
	if (months || years) {
		snprintf(outbuf, sizeof(buf), "%lu Months ", months);
		strcat(buf, outbuf);
	}
	if (days || months || years) {
		snprintf(outbuf, sizeof(buf), "%lu Days ", days);
		strcat(buf, outbuf);
	}
	if (hours || days || months || years) {
		snprintf(outbuf, sizeof(buf), "%lu Hours ", hours);
		strcat(buf, outbuf);
	}
	if (minutes || hours || days || months || years) {
		snprintf(outbuf, sizeof(buf), "%lu Minutes ", minutes);
		strcat(buf, outbuf);
	}
	snprintf(outbuf, sizeof(outbuf), "%lu Seconds ", seconds);
	strcat(buf, outbuf);
       	write_portal_cleol(portal, buf, row, 2, BRITEWHITE | BGBLUE);
	row++;

	FILE *fp = fopen("/proc/loadavg", "rb");
	if (fp) {
		char *s, line[100];

		s = fgets(line, 99, fp);
		if (s) { 
		 	char *str = s;
			float min1, min5, min15;
			int running_threads, total_threads;
			
			while (*str) {
				if (*str == '\n') {
					*str = '\0';
					break;
				}
				str++;
			}	

                	if (sscanf(s, "%f %f %f %d/%d",
				&min1,
				&min5,
				&min15,
				&running_threads,
				&total_threads) == 5) {

			   snprintf(outbuf, sizeof(outbuf), "Load Average:  1 min %2.2f,  5 min %2.2f, 15 min %2.2f, run %d, all %d",
					min1, min5, min15, running_threads, total_threads);
       			   write_portal_cleol(portal, outbuf, row++, 2, BRITEWHITE | BGBLUE);
			}
		}
		fclose(fp);
	}

 	// get total combined CPU usage first
	s = get_cpu_load(st, 0, outbuf, 1024, 1);
	if (s) {
       		write_portal_cleol(portal, s, row++, 2, BRITEWHITE | BGBLUE);
	}

	if (flags & LONG_FORMAT) {
		int y;
		ULONG ch = get_horizontal_frame(portal);
		if (ch) {
			for (y=2; y < 75; y++) {
				write_portal_char(portal, (BYTE)ch, row, y, BRITEWHITE | BGBLUE);
			}
			row++;
		}

	 	// get individual CPU usage 
	    	for (n = 0; n < st->cpus; n++) {
			s = get_cpu_load(st, n, outbuf, 1024, 0);
			if (s) {
       				write_portal_cleol(portal, s, row++, 2, BRITEWHITE | BGBLUE);
			}	
		}
	} 
	int y;
	ULONG ch = get_horizontal_frame(portal);
	if (ch) {
		for (y=2; y < 75; y++) {
			write_portal_char(portal, (BYTE)ch, row, y, BRITEWHITE | BGBLUE);
		}
		row++;
	}

	struct mem_stats_list ml;
	memset(&ml, 0, sizeof(struct mem_stats_list));
        get_mem_stats(&ml);

  	snprintf(buf, sizeof(buf), "KiB Mem  %7llu total, %7llu free, %7llu used, %7llu buffers",
		ml.mem_total, ml.mem_free, ml.mem_allocated, ml.buffers);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

  	snprintf(buf, sizeof(buf), "KiB Swap %7llu total, %7llu free, %7llu used, %7llu available",
		ml.swap_total, ml.swap_free, ml.swap_allocated, ml.mem_available);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	row++;

	scan_diskstats(pr);

  	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", pr->total_p_read ? (pr->total_sectors_read - pr->total_p_read) * 512 : 0, 19);
	snprintf(buf, sizeof(buf), "Disk Reads/Second         :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", pr->total_p_written ? (pr->total_sectors_written - pr->total_p_written) * 512 : 0, 19);
	snprintf(buf, sizeof(buf), "Disk Writes/Second        :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", pr->total_sectors_read * 512, 19);
	snprintf(buf, sizeof(buf), "Total Disk Reads          :   %22s", w);
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", pr->total_sectors_written * 512, 19);
	snprintf(buf, sizeof(buf), "Total Disk Writes         :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	util = pr->total_p_iotime ? (float)((float)(pr->total_io_time - pr->total_p_iotime) / 1000) * 100 : 0;
	if (util > 100)
	   util = 100;
	snprintf(nbuf, sizeof(nbuf), "%2.1f", util);
	snprintf(buf, sizeof(buf), "Total Disk Utilization    :   %22s%%", nbuf);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	row++;

	get_network_totals(list);

        w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", list->previous->rx_bytes ? list->current->rx_bytes - list->previous->rx_bytes : 0, 19);
        snprintf(buf, sizeof(buf), "Network Receives/Second   :   %22s", w);
        write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

        w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", list->previous->tx_bytes ? list->current->tx_bytes - list->previous->tx_bytes : 0, 19);
        snprintf(buf, sizeof(buf), "Network Transmits/Second  :   %22s", w);
        write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

        w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", list->previous->rx_packets ? list->current->rx_packets - list->previous->rx_packets : 0, 19);
        snprintf(buf, sizeof(buf), "Network Receive Pkts/Sec  :   %22s", w);
        write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

        w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", list->previous->tx_packets ? list->current->tx_packets - list->previous->tx_packets : 0, 19);
        snprintf(buf, sizeof(buf), "Network Transmit Pkts/Sec :   %22s", w);
        write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

        w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", list->current->rx_bytes, 19);
        snprintf(buf, sizeof(buf), "Total Receive Bytes       :   %22s", w);
        write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

        w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", list->current->tx_bytes, 19);
        snprintf(buf, sizeof(buf), "Total Transmit Bytes      :   %22s", w);
        write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

        w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", list->current->rx_packets, 19);
        snprintf(buf, sizeof(buf), "Total Receive Packets     :   %22s", w);
        write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

        w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", list->current->tx_packets, 19);
        snprintf(buf, sizeof(buf), "Total Transmit Packets    :   %22s", w);
        write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	row++;

	stats_shm = shm_open(STATS_MEM_NAME, O_RDONLY, 0); 
	if (stats_shm > 0) {
		if ((stats_ptr = (GLOBAL *)mmap(NULL, sizeof(GLOBAL), PROT_READ, MAP_SHARED, stats_shm, 0)) == MAP_FAILED)
			stats_ptr = NULL;
	}	

	if ((mutex_sem = sem_open(SEM_MUTEX_NAME, 0, 0, 0)) == SEM_FAILED) {
		mutex_sem = NULL;
	}

	if (stats_ptr) {
		ctx->pages_per_second = stats_ptr->pages_per_second;
		ctx->bytes_per_second = stats_ptr->bytes_per_second;
		ctx->dropped_per_second = stats_ptr->dropped_per_second;
		ctx->errors_per_second = stats_ptr->errors_per_second;
		ctx->aborts_per_second = stats_ptr->aborts_per_second;
		ctx->skipped_per_second = stats_ptr->skipped_per_second;
		ctx->total_pages = stats_ptr->total_pages;
		ctx->total_bytes = stats_ptr->total_bytes;
		ctx->total_dropped = stats_ptr->total_dropped;
		ctx->total_errors = stats_ptr->total_errors;
		ctx->total_aborts = stats_ptr->total_aborts;
		ctx->total_skipped = stats_ptr->total_skipped;
		ctx->total_allocation = stats_ptr->total_allocation;
		ctx->total_process = stats_ptr->total_process;
		ctx->total_connection = stats_ptr->total_connection;
		ctx->total_queue = stats_ptr->total_queue;
		ctx->avg_pages_per_second = stats_ptr->avg_pages_per_second;
		ctx->avg_bytes_per_second = stats_ptr->avg_bytes_per_second;
		ctx->avg_dropped_per_second = stats_ptr->avg_dropped_per_second;
		ctx->avg_errors_per_second = stats_ptr->avg_errors_per_second;
		ctx->avg_aborts_per_second = stats_ptr->avg_aborts_per_second;
		ctx->avg_skipped_per_second = stats_ptr->avg_skipped_per_second;
		ctx->peak_pages_per_second = stats_ptr->peak_pages_per_second;
		ctx->peak_bytes_per_second = stats_ptr->peak_bytes_per_second;
		ctx->peak_dropped_per_second = stats_ptr->peak_dropped_per_second;
		ctx->peak_errors_per_second = stats_ptr->peak_errors_per_second;
		ctx->peak_aborts_per_second = stats_ptr->peak_aborts_per_second;
		ctx->peak_skipped_per_second = stats_ptr->peak_skipped_per_second;

		strncpy(ctx->db_host, stats_ptr->db_host, MAX_SQL_HOSTNAME);
		ctx->db_host[MAX_SQL_HOSTNAME] = '\0';

		strncpy(ctx->db_name, stats_ptr->db_name, MAX_SQL_DATABASE_NAME);
		ctx->db_name[MAX_SQL_DATABASE_NAME] = '\0';

		strncpy(ctx->db_table, stats_ptr->db_table, MAX_SQL_TABLE_NAME);
		ctx->db_table[MAX_SQL_TABLE_NAME] = '\0';

		strncpy(ctx->db_user, stats_ptr->db_user, MAX_SQL_USER_NAME);
		ctx->db_user[MAX_SQL_USER_NAME] = '\0';

		strncpy(ctx->db_pass, "******", MAX_SQL_PASSWORD);
		ctx->db_pass[MAX_SQL_PASSWORD] = '\0';

		strncpy(ctx->db_path, stats_ptr->db_path, MAX_PATH_LENGTH);
		ctx->db_path[MAX_PATH_LENGTH] = '\0';

		ctx->db_free_space_threshold = stats_ptr->db_free_space_threshold;
		ctx->db_max_size = stats_ptr->db_max_size;
		ctx->skip_length = stats_ptr->skip_length;
		ctx->condensed_max_length = stats_ptr->condensed_max_length;
		ctx->show_skipped_requests = stats_ptr->show_skipped_requests;
		ctx->db_mode = stats_ptr->db_mode;
		ctx->db_init_startup = stats_ptr->db_init_startup;
		ctx->async_threads = stats_ptr->async_threads;
		ctx->sync_threads = stats_ptr->sync_threads;
		ctx->license = stats_ptr->license;
		memmove(ctx->license_data, stats_ptr->license_data, 128);
	}

        write_portal_line(portal, row++, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "LEAF Server %s", stats_ptr ? "Statistics" : "is OFFLINE");
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
        write_portal_line(portal, row++, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->async_threads, 18);
	snprintf(buf, sizeof(buf), "Pending Async I/O         :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->sync_threads, 18);
	snprintf(buf, sizeof(buf), "Pending Sync I/O          :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->pages_per_second, 18);
	snprintf(buf, sizeof(buf), "Pages/Second              :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->bytes_per_second, 18);
	snprintf(buf, sizeof(buf), "Bytes/Second              :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->dropped_per_second, 18);
	snprintf(buf, sizeof(buf), "Dropped/Second            :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->errors_per_second, 18);
	snprintf(buf, sizeof(buf), "Errors/Second             :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->aborts_per_second, 18);
	snprintf(buf, sizeof(buf), "Aborts/Second             :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->skipped_per_second, 18);
	snprintf(buf, sizeof(buf), "Skipped/Second            :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_pages, 18);
	snprintf(buf, sizeof(buf), "Total Pages               :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_bytes, 18);
	snprintf(buf, sizeof(buf), "Total Bytes               :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_dropped, 18);
	snprintf(buf, sizeof(buf), "Total Dropped             :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_errors, 18);
	snprintf(buf, sizeof(buf), "Total Errors              :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_aborts, 18);
	snprintf(buf, sizeof(buf), "Total Aborts              :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_skipped, 18);
	snprintf(buf, sizeof(buf), "Total Skipped             :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_allocation, 18);
	snprintf(buf, sizeof(buf), "Total Allocation Errors   :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_process, 18);
	snprintf(buf, sizeof(buf), "Total Process Errors      :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_connection, 18);
	snprintf(buf, sizeof(buf), "Total Connection Errors   :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_queue, 18);
	snprintf(buf, sizeof(buf), "Total Queueing Drops      :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->avg_pages_per_second, 18);
	snprintf(buf, sizeof(buf), "Average Pages/Second      :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->avg_bytes_per_second, 18);
	snprintf(buf, sizeof(buf), "Average Bytes/Second      :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->avg_dropped_per_second, 18);
	snprintf(buf, sizeof(buf), "Average Dropped/Second    :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->avg_errors_per_second, 18);
	snprintf(buf, sizeof(buf), "Average Errors/Second     :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->avg_aborts_per_second, 18);
	snprintf(buf, sizeof(buf), "Average Aborts/Second     :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->avg_skipped_per_second, 18);
	snprintf(buf, sizeof(buf), "Average Skipped/Second    :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->peak_pages_per_second, 18);
	snprintf(buf, sizeof(buf), "Peak Pages/Second         :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->peak_bytes_per_second, 18);
	snprintf(buf, sizeof(buf), "Peak Bytes/Second         :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->peak_dropped_per_second, 18);
	snprintf(buf, sizeof(buf), "Peak Dropped/Second       :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->peak_errors_per_second, 18);
	snprintf(buf, sizeof(buf), "Peak Errors/Second        :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->peak_aborts_per_second, 18);
	snprintf(buf, sizeof(buf), "Peak Aborts/Second        :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->peak_skipped_per_second, 18);
	snprintf(buf, sizeof(buf), "Peak Skipped/Second       :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

#if 0
	snprintf(buf, sizeof(buf), "Leaf Product License      :   %22s", ctx->license ? "VALID" : "UNLICENSED");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "License Key           %02X%02X%02X%02X-%02X%02X%02X%02X-%02X%02X%02X%02X%02X%02X",
				ctx->license_data[0], ctx->license_data[1], ctx->license_data[2], 
				ctx->license_data[3], ctx->license_data[4], ctx->license_data[5], 
				ctx->license_data[6], ctx->license_data[7], ctx->license_data[8], 
				ctx->license_data[9], ctx->license_data[10], ctx->license_data[11],
				ctx->license_data[12], ctx->license_data[13]); 
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
#else
	snprintf(buf, sizeof(buf), "Leaf Product License      :   %22s", "LGPL");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
#endif
	row++;
        write_portal_line(portal, row++, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "MYSQL %s", stats_ptr ? "Statistics" : "is OFFLINE");
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
        write_portal_line(portal, row++, BRITEWHITE | BGBLUE);

	snprintf(buf, sizeof(buf), "SQL Server Hostname       :   %22s", ctx->db_host[0] ? ctx->db_host : "OFFLINE");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "SQL Database Name         :   %22s", ctx->db_name[0] ? ctx->db_name : "OFFLINE");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "SQL Table Name            :   %22s", ctx->db_table[0] ? ctx->db_table : "OFFLINE");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "SQL User Account          :   %22s", ctx->db_user[0] ? ctx->db_user : "OFFLINE");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "SQL Password              :   %22s", ctx->db_pass);
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "SQL Database Path         :   %22s", ctx->db_path);
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "SQL Database Mode         :   %22s", ctx->db_mode ? "Ring Buffer" : "Insert Mode");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%ld", ctx->db_free_space_threshold, 18);
	snprintf(buf, sizeof(buf), "SQL Free Space Threshold  :   %22s", w);
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", mysql_free_size(), 18);
	snprintf(buf, sizeof(buf), "SQL Current Free Space    :   %22s", w);
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

        if (!ctx->db_max_size) {
		snprintf(buf, sizeof(buf), "SQL Table Max Records     :   %22s", "UNLIMITED");
	}
        else {
		w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%ld", ctx->db_max_size, 18);
		snprintf(buf, sizeof(buf), "SQL Table Max Records     :   %22s", w);
	}
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

        if (!ctx->skip_length) {
		snprintf(buf, sizeof(buf), "HTML Skip Length          :   %22s", "UNLIMITED");
	}
        else {
		w = comma_snprintf(nbuf, sizeof(nbuf), "%ld", ctx->skip_length);
		snprintf(buf, sizeof(buf), "HTML Skip Length          :   %22s", w);
	}
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
        if (!ctx->condensed_max_length) {
		snprintf(buf, sizeof(buf), "HTML Extract Max Length   :   %22s", "UNLIMITED");
	}
        else {
		w = comma_snprintf(nbuf, sizeof(nbuf), "%ld", ctx->condensed_max_length);
		snprintf(buf, sizeof(buf), "HTML Extract Max Length   :   %22s", w);
	}
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "Show Skipped Content      :   %22s", ctx->show_skipped_requests ? "ON" : "OFF");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "Wipe Database at Startup  :   %22s", ctx->db_init_startup ? "ON" : "OFF");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	
	write_portal_cleol(portal, (const char *)" ", row++, 2, BRITEWHITE | BGBLUE);

	if (mutex_sem) {
		sem_close(mutex_sem);
		mutex_sem = NULL;
	}

	if (stats_ptr) {
		munmap(stats_ptr, sizeof(GLOBAL));
		stats_ptr = NULL;
	}
	if (stats_shm > 0) {
		close(stats_shm);
		stats_shm = 0;
	}

	return 1;
}

char *get_mount_swap(char *buf, size_t len, char *dev)
{
	char *p = dev;
	return p;	
}

int display_disk_summary(int portal, PSTATE *pr, int flags)
{
	int row = 0, i;
	char buf[4096], *mount;
	char nbuf[1024], *w;
	char rbuf[1024], *read;
	char wbuf[1024], *write;
	char rbufsec[1024], *reads;
	char wbufsec[1024], *writes;
	float util;

	row = 0;
	scan_diskstats(pr);

	if (flags & LONG_FORMAT) {
		snprintf(buf, sizeof(buf), "General Disk Statistics");
	       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
		int y;
		char ch = get_horizontal_frame(portal);
		if (ch) {
			for (y=2; y < (get_screen_cols() - 6); y++) {
				write_portal_char(portal, (BYTE)ch, row, y, BRITEWHITE | BGBLUE);
			}
			row++;
		}
        	//write_portal_line(portal, row++, BRITEWHITE | BGBLUE);

		w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", pr->total_p_read ? (pr->total_sectors_read - pr->total_p_read) * 512 : 0, 19);
		snprintf(buf, sizeof(buf), "Disk Reads/Second         :   %22s", w);
	       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

		w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", pr->total_p_written ? (pr->total_sectors_written - pr->total_p_written) * 512 : 0, 19);
		snprintf(buf, sizeof(buf), "Disk Writes/Second        :   %22s", w);
	       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

		w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", pr->total_sectors_read * 512, 19);
		snprintf(buf, sizeof(buf), "Total Disk Reads          :   %22s", w);
	       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

		w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", pr->total_sectors_written * 512, 19);
		snprintf(buf, sizeof(buf), "Total Disk Writes         :   %22s", w);
	       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

		util = pr->total_p_iotime ? (float)((float)(pr->total_io_time - pr->total_p_iotime) / 1000) * 100 : 0;
		if (util > 100)
		   util = 100;
		snprintf(nbuf, sizeof(nbuf), "%2.1f", util);
		snprintf(buf, sizeof(buf), "Total Disk Utilization    :   %22s%%", nbuf);
	       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

		row++;

		write_portal_cleol(portal, "device            reads        writes      reads/sec   writes/sec  ut%", row++, 2, BRITEWHITE | BGBLUE);

		ch = get_horizontal_frame(portal);
		if (ch) {
			for (y=2; y < (get_screen_cols() - 6); y++) {
				write_portal_char(portal, (BYTE)ch, row, y, BRITEWHITE | BGBLUE);
			}
			row++;
		}

		for (i=0; i < pr->n_part; i++) {
			read = comma_snprintf_scaled(rbuf, sizeof(rbuf), "%llu", pr->p[i].sectors_read * 512, 6);
			write = comma_snprintf_scaled(wbuf, sizeof(wbuf), "%llu", pr->p[i].sectors_written * 512, 6);
			reads = comma_snprintf_scaled(rbufsec, sizeof(rbufsec), "%llu",
					pr->p[i].p_read ? (pr->p[i].sectors_read - pr->p[i].p_read) * 512 : 0, 6);
			writes = comma_snprintf_scaled(wbufsec, sizeof(wbufsec), "%llu",
					pr->p[i].p_written ? (pr->p[i].sectors_written - pr->p[i].p_written) * 512 : 0, 6);

			util = pr->p[i].p_iotime ? (float)((float)(pr->p[i].io_time - pr->p[i].p_iotime) / 1000) * 100 : 0;
			if (util > 100)
			   util = 100;
			snprintf(buf, sizeof(buf), "%03d:%03d %6s  %9s     %9s      %9s    %9s  %2.1f%%",
				pr->p[i].major, pr->p[i].minor, pr->p[i].device_name, read, write, reads, writes, util);
       			write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
		}
		row++;

		write_portal_cleol(portal, "device       reads/merged  writes/merged      pending/io     io/weight",
				 row++, 2, BRITEWHITE | BGBLUE);
		ch = get_horizontal_frame(portal);
		if (ch) {
			for (y=2; y < (get_screen_cols() - 6); y++) {
				write_portal_char(portal, (BYTE)ch, row, y, BRITEWHITE | BGBLUE);
			}
			row++;
		}

		for (i=0; i < pr->n_part; i++) {
			read = comma_snprintf_scaled(rbuf, sizeof(rbuf), "%llu", pr->p[i].reads_merged, 6);
			write = comma_snprintf_scaled(wbuf, sizeof(wbuf), "%llu", pr->p[i].writes_merged, 6);
			reads = comma_snprintf_scaled(rbufsec, sizeof(rbufsec), "%llu", pr->p[i].io_active, 6);
			writes = comma_snprintf_scaled(wbufsec, sizeof(wbufsec), "%llu", 
				pr->p[i].p_io_weight ? (pr->p[i].io_weight - pr->p[i].p_io_weight) : 0, 6);
			snprintf(buf, sizeof(buf), "%03d:%03d %6s    %9s      %9s     %9s     %9s ms",
				pr->p[i].major, pr->p[i].minor, pr->p[i].device_name, read, write, reads, writes);
       			write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
		}
		row++;

		write_portal_cleol(portal, "device              mounted",
				 row++, 2, BRITEWHITE | BGBLUE);
		ch = get_horizontal_frame(portal);
		if (ch) {
			for (y=2; y < (get_screen_cols() - 6); y++) {
				write_portal_char(portal, (BYTE)ch, row, y, BRITEWHITE | BGBLUE);
			}
			row++;
		}

		for (i=0; i < pr->n_part; i++) {
			mount = get_mount_swap(nbuf, sizeof(nbuf), pr->p[i].device_name);
			snprintf(buf, sizeof(buf), "%03d:%03d %6s    %9s", 
				pr->p[i].major, pr->p[i].minor, pr->p[i].device_name, mount);
       			write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
		}
		row++;
	}

	if (flags & SHORT_FORMAT) {
		read = comma_snprintf_scaled(rbuf, sizeof(rbuf), "%llu", pr->total_sectors_read * 512, 6);
		write = comma_snprintf_scaled(wbuf, sizeof(wbuf), "%llu", pr->total_sectors_written * 512, 6);
		reads = comma_snprintf_scaled(rbufsec, sizeof(rbufsec), "%llu", pr->total_p_read
					? (pr->total_sectors_read - pr->total_p_read) * 512 : 0, 6);
		writes = comma_snprintf_scaled(wbufsec, sizeof(wbufsec), "%llu", pr->total_p_written
					? (pr->total_sectors_written - pr->total_p_written) * 512 : 0, 6);
		util = pr->total_p_iotime ? (float)((float)(pr->total_io_time - pr->total_p_iotime) / 1000) * 100 : 0;
		if (util > 100)
		   util = 100;
		snprintf(buf, sizeof(buf), "disk(s) %10s   reads, %10s   writes,  %10s rd/sec,  %10s wr/sec,  u%% %2.1f%%",
			 read, write, reads, writes, util);
		write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	}

	return 1;
}

#define ICAP_STATS_MEM_NAME "/icapstats"
#define ICAP_SEM_MUTEX_NAME "/icapstatsmutex"
#define ICAP_STATS_MEM_SIZE 0x100000

int display_cicap_summary(int portal)
{
	int row, i, j;
	char buf[1024], *p;
	char nbuf[1024], last = '\0';
	char *icap_stats_ptr = NULL;
	sem_t *mutex_sem = NULL;
	int icap_stats_shm;
	long len;

	icap_stats_shm = shm_open(ICAP_STATS_MEM_NAME, O_RDONLY, 0); 
	if (icap_stats_shm > 0) {
		if ((icap_stats_ptr = (char *)mmap(NULL, ICAP_STATS_MEM_SIZE, PROT_READ, MAP_SHARED, icap_stats_shm, 0)) == MAP_FAILED)
			icap_stats_ptr = NULL;
	}	

	if ((mutex_sem = sem_open(ICAP_SEM_MUTEX_NAME, 0, 0, 0)) == SEM_FAILED) {
		mutex_sem = NULL;
	}

	row = 0;
	if (icap_stats_ptr) {
		len = strlen(icap_stats_ptr) + 1;
		if (len > ICAP_STATS_MEM_SIZE)
			len = ICAP_STATS_MEM_SIZE;

		snprintf(nbuf, sizeof(nbuf), "ICAP Server Statistics (%ld bytes)", len);
		write_portal_cleol(portal, (const char *)nbuf, row++, 2, BRITEWHITE | BGBLUE);
		int y;
		char ch = get_horizontal_frame(portal);
		if (ch) {
			for (y=2; y < (get_screen_cols() - 6); y++) {
				write_portal_char(portal, (BYTE)ch, row, y, BRITEWHITE | BGBLUE);
			}
			row++;
		}
		row++;
	       	//write_portal_line(portal, row++, BRITEWHITE | BGBLUE);

	        p = icap_stats_ptr;
		for (i=0,j=0; p && i < len; i++) {
			if (p[i] == '=') {
				buf[j++] = get_horizontal_frame(portal);		
				last = p[i];
			}
			else if (p[i] == '\n') {
				if (last == '\n') {
					buf[j++] = ' ';		
					buf[j++] = '\0';		
				}
				else {
					buf[j++] = '\0';		
				}
				snprintf(nbuf, sizeof(nbuf), "%s", buf);
				if (nbuf[0])
					write_portal_cleol(portal, (const char *)nbuf, row++, 2, BRITEWHITE | BGBLUE);
				j = 0;
				last = p[i];
				continue;
			}
			else if (p[i] == '\0') {
				buf[j++] = '\0';		
				snprintf(nbuf, sizeof(nbuf), "%s", buf);
				if (nbuf[0])
					write_portal_cleol(portal, (const char *)nbuf, row++, 2, BRITEWHITE | BGBLUE);
				j = 0;
				break;
			}
			else {
				if (j < 1024) {
					buf[j++] = p[i];		
				}
				last = p[i];
			}
		}
	}
	else {
		len = 0;
		snprintf(nbuf, sizeof(nbuf), "ICAP Server is OFFLINE");
		write_portal_cleol(portal, (const char *)nbuf, row++, 2, BRITEWHITE | BGBLUE);
	        write_portal_line(portal, row++, BRITEWHITE | BGBLUE);
	} 

	write_portal_cleol(portal, (const char *)" ", row++, 2, BRITEWHITE | BGBLUE);

	if (mutex_sem) {
		sem_close(mutex_sem);
		mutex_sem = NULL;
	}
	if (icap_stats_ptr) {
		munmap(icap_stats_ptr, ICAP_STATS_MEM_SIZE);
		icap_stats_ptr = NULL;
	}
	if (icap_stats_shm > 0) {
		close(icap_stats_shm);
		icap_stats_shm = 0;
	}

	return 1;
}

void *cicap_routine(void *p)
{
   NP *np = (NP *)p;
   int portal = np ? np->portal : 0;
   int state;
   
   while (cicapactive && p)
   {
      pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
      clear_portal_storage(portal);
      display_cicap_summary(portal);
      update_static_portal(portal);
      pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &state);
      sleep(1);
      if (!get_sleep_count(portal))
         clear_portal_focus(portal);
   }
   return NULL;
}

void *leaf_disk_routine(void *p)
{
   NP *np = (NP *)p;
   int portal = np ? np->portal : 0;
   PSTATE *pr = np ? np->pstate : NULL;
   int state;

   while (leafdiskactive && p)
   {
      pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
      display_disk_summary(portal, pr, LONG_FORMAT);
      update_static_portal(portal);
      pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &state);
      sleep(1);
      if (!get_sleep_count(portal))
         clear_portal_focus(portal);
   }
   return NULL;
}

void *leaf_summary_routine(void *p)
{
   NP *np = (NP *)p;
   int portal = np ? np->portal : 0;
   STATE *st = np ? np->state : NULL;
   PSTATE *pr = np ? np->pstate : NULL;
   LCTX *ctx = np ? np->ctx : NULL;
   int state;

   while (leafsumactive && p && np)
   {
      pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
      display_leaf_summary(portal, st, pr, ctx, &np->list, LONG_FORMAT);
      update_static_portal(portal);
      pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &state);
      sleep(1);
      if (!get_sleep_count(portal))
         clear_portal_focus(portal);
   }
   return NULL;
}

int mysql_summary(int portal, LCTX *ctx)
{
	GLOBAL *stats_ptr = NULL;
	sem_t *mutex_sem = NULL;
	int stats_shm, row, y;
	char buf[8192];
	char nbuf[1024], *w;
	
	if (!ctx) {
       	   write_portal_cleol(portal, "leafmon: context pointers not set in display_leaf_summary", 0, 2, BRITEWHITE | BGBLUE);
	   return 0;
	}
	
	stats_shm = shm_open(STATS_MEM_NAME, O_RDONLY, 0); 
	if (stats_shm > 0) {
		if ((stats_ptr = (GLOBAL *)mmap(NULL, sizeof(GLOBAL), PROT_READ, MAP_SHARED, stats_shm, 0)) == MAP_FAILED)
			stats_ptr = NULL;
	}	

	if ((mutex_sem = sem_open(SEM_MUTEX_NAME, 0, 0, 0)) == SEM_FAILED) {
		mutex_sem = NULL;
	}

	if (stats_ptr) {
		ctx->pages_per_second = stats_ptr->pages_per_second;
		ctx->bytes_per_second = stats_ptr->bytes_per_second;
		ctx->dropped_per_second = stats_ptr->dropped_per_second;
		ctx->errors_per_second = stats_ptr->errors_per_second;
		ctx->aborts_per_second = stats_ptr->aborts_per_second;
		ctx->skipped_per_second = stats_ptr->skipped_per_second;
		ctx->total_pages = stats_ptr->total_pages;
		ctx->total_bytes = stats_ptr->total_bytes;
		ctx->total_dropped = stats_ptr->total_dropped;
		ctx->total_errors = stats_ptr->total_errors;
		ctx->total_aborts = stats_ptr->total_aborts;
		ctx->total_skipped = stats_ptr->total_skipped;
		ctx->total_allocation = stats_ptr->total_allocation;
		ctx->total_process = stats_ptr->total_process;
		ctx->total_connection = stats_ptr->total_connection;
		ctx->total_queue = stats_ptr->total_queue;
		ctx->avg_pages_per_second = stats_ptr->avg_pages_per_second;
		ctx->avg_bytes_per_second = stats_ptr->avg_bytes_per_second;
		ctx->avg_dropped_per_second = stats_ptr->avg_dropped_per_second;
		ctx->avg_errors_per_second = stats_ptr->avg_errors_per_second;
		ctx->avg_aborts_per_second = stats_ptr->avg_aborts_per_second;
		ctx->avg_skipped_per_second = stats_ptr->avg_skipped_per_second;
		ctx->peak_pages_per_second = stats_ptr->peak_pages_per_second;
		ctx->peak_bytes_per_second = stats_ptr->peak_bytes_per_second;
		ctx->peak_dropped_per_second = stats_ptr->peak_dropped_per_second;
		ctx->peak_errors_per_second = stats_ptr->peak_errors_per_second;
		ctx->peak_aborts_per_second = stats_ptr->peak_aborts_per_second;
		ctx->peak_skipped_per_second = stats_ptr->peak_skipped_per_second;

		strncpy(ctx->db_host, stats_ptr->db_host, MAX_SQL_HOSTNAME);
		ctx->db_host[MAX_SQL_HOSTNAME] = '\0';

		strncpy(ctx->db_name, stats_ptr->db_name, MAX_SQL_DATABASE_NAME);
		ctx->db_name[MAX_SQL_DATABASE_NAME] = '\0';

		strncpy(ctx->db_table, stats_ptr->db_table, MAX_SQL_TABLE_NAME);
		ctx->db_table[MAX_SQL_TABLE_NAME] = '\0';

		strncpy(ctx->db_user, stats_ptr->db_user, MAX_SQL_USER_NAME);
		ctx->db_user[MAX_SQL_USER_NAME] = '\0';

		strncpy(ctx->db_pass, "******", MAX_SQL_PASSWORD);
		ctx->db_pass[MAX_SQL_PASSWORD] = '\0';

		strncpy(ctx->db_path, stats_ptr->db_path, MAX_PATH_LENGTH);
		ctx->db_path[MAX_PATH_LENGTH] = '\0';

		ctx->db_free_space_threshold = stats_ptr->db_free_space_threshold;
		ctx->db_max_size = stats_ptr->db_max_size;
		ctx->skip_length = stats_ptr->skip_length;
		ctx->condensed_max_length = stats_ptr->condensed_max_length;
		ctx->show_skipped_requests = stats_ptr->show_skipped_requests;
		ctx->db_mode = stats_ptr->db_mode;
		ctx->db_init_startup = stats_ptr->db_init_startup;
		ctx->async_threads = stats_ptr->async_threads;
		ctx->sync_threads = stats_ptr->sync_threads;
		ctx->license = stats_ptr->license;
		memmove(ctx->license_data, stats_ptr->license_data, 128);
	}

	row = 0;
	snprintf(buf, sizeof(buf), "LEAF Server %s", stats_ptr ? "Statistics" : "is OFFLINE");
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	char ch = get_horizontal_frame(portal);
	if (ch) {
		for (y=2; y < (get_screen_cols() - 6); y++) {
			write_portal_char(portal, (BYTE)ch, row, y, BRITEWHITE | BGBLUE);
		}
		row++;
	}

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->async_threads, 18);
	snprintf(buf, sizeof(buf), "Pending Async I/O         :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->sync_threads, 18);
	snprintf(buf, sizeof(buf), "Pending Sync I/O          :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->pages_per_second, 18);
	snprintf(buf, sizeof(buf), "Pages/Second              :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->bytes_per_second, 18);
	snprintf(buf, sizeof(buf), "Bytes/Second              :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->dropped_per_second, 18);
	snprintf(buf, sizeof(buf), "Dropped/Second            :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->errors_per_second, 18);
	snprintf(buf, sizeof(buf), "Errors/Second             :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->aborts_per_second, 18);
	snprintf(buf, sizeof(buf), "Aborts/Second             :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->skipped_per_second, 18);
	snprintf(buf, sizeof(buf), "Skipped/Second            :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_pages, 18);
	snprintf(buf, sizeof(buf), "Total Pages               :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_bytes, 18);
	snprintf(buf, sizeof(buf), "Total Bytes               :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_dropped, 18);
	snprintf(buf, sizeof(buf), "Total Dropped             :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_errors, 18);
	snprintf(buf, sizeof(buf), "Total Errors              :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_aborts, 18);
	snprintf(buf, sizeof(buf), "Total Aborts              :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_skipped, 18);
	snprintf(buf, sizeof(buf), "Total Skipped             :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_allocation, 18);
	snprintf(buf, sizeof(buf), "Total Allocation Errors   :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_process, 18);
	snprintf(buf, sizeof(buf), "Total Process Errors      :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_connection, 18);
	snprintf(buf, sizeof(buf), "Total Connection Errors   :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->total_queue, 18);
	snprintf(buf, sizeof(buf), "Total Queueing Drops      :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->avg_pages_per_second, 18);
	snprintf(buf, sizeof(buf), "Average Pages/Second      :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->avg_bytes_per_second, 18);
	snprintf(buf, sizeof(buf), "Average Bytes/Second      :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->avg_dropped_per_second, 18);
	snprintf(buf, sizeof(buf), "Average Dropped/Second    :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->avg_errors_per_second, 18);
	snprintf(buf, sizeof(buf), "Average Errors/Second     :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->avg_aborts_per_second, 18);
	snprintf(buf, sizeof(buf), "Average Aborts/Second     :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->avg_skipped_per_second, 18);
	snprintf(buf, sizeof(buf), "Average Skipped/Second    :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->peak_pages_per_second, 18);
	snprintf(buf, sizeof(buf), "Peak Pages/Second         :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->peak_bytes_per_second, 18);
	snprintf(buf, sizeof(buf), "Peak Bytes/Second         :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->peak_dropped_per_second, 18);
	snprintf(buf, sizeof(buf), "Peak Dropped/Second       :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->peak_errors_per_second, 18);
	snprintf(buf, sizeof(buf), "Peak Errors/Second        :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->peak_aborts_per_second, 18);
	snprintf(buf, sizeof(buf), "Peak Aborts/Second        :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", ctx->peak_skipped_per_second, 18);
	snprintf(buf, sizeof(buf), "Peak Skipped/Second       :   %22s", w);
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

#if 0
	snprintf(buf, sizeof(buf), "Leaf Product License      :   %22s", ctx->license ? "VALID" : "UNLICENSED");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "License Key           %02X%02X%02X%02X-%02X%02X%02X%02X-%02X%02X%02X%02X%02X%02X",
				ctx->license_data[0], ctx->license_data[1], ctx->license_data[2], 
				ctx->license_data[3], ctx->license_data[4], ctx->license_data[5], 
				ctx->license_data[6], ctx->license_data[7], ctx->license_data[8], 
				ctx->license_data[9], ctx->license_data[10], ctx->license_data[11],
				ctx->license_data[12], ctx->license_data[13]); 
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	row++;
#else
	snprintf(buf, sizeof(buf), "Leaf Product License      :   %22s", "LGPL");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
#endif

	ch = get_horizontal_frame(portal);
	if (ch) {
		for (y=2; y < (get_screen_cols() - 6); y++) {
			write_portal_char(portal, (BYTE)ch, row, y, BRITEWHITE | BGBLUE);
		}
		row++;
	}

	snprintf(buf, sizeof(buf), "MYSQL %s", stats_ptr ? "Statistics" : "is OFFLINE");
       	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	ch = get_horizontal_frame(portal);
	if (ch) {
		for (y=2; y < (get_screen_cols() - 6); y++) {
			write_portal_char(portal, (BYTE)ch, row, y, BRITEWHITE | BGBLUE);
		}
		row++;
	}

	snprintf(buf, sizeof(buf), "SQL Server Hostname       :   %22s", ctx->db_host[0] ? ctx->db_host : "OFFLINE");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "SQL Database Name         :   %22s", ctx->db_name[0] ? ctx->db_name : "OFFLINE");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "SQL Table Name            :   %22s", ctx->db_table[0] ? ctx->db_table : "OFFLINE");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "SQL User Account          :   %22s", ctx->db_user[0] ? ctx->db_user : "OFFLINE");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "SQL Password              :   %22s", ctx->db_pass);
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "SQL Database Path         :   %22s", ctx->db_path);
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "SQL Database Mode         :   %22s", ctx->db_mode ? "Ring Buffer" : "Insert Mode");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%ld", ctx->db_free_space_threshold, 18);
	snprintf(buf, sizeof(buf), "SQL Free Space Threshold  :   %22s", w);
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%llu", mysql_free_size(), 18);
	snprintf(buf, sizeof(buf), "SQL Current Free Space    :   %22s", w);
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

        if (!ctx->db_max_size) {
		snprintf(buf, sizeof(buf), "SQL Table Max Records     :   %22s", "UNLIMITED");
	}
        else {
		w = comma_snprintf_scaled(nbuf, sizeof(nbuf), "%ld", ctx->db_max_size, 18);
		snprintf(buf, sizeof(buf), "SQL Table Max Records     :   %22s", w);
	}
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

        if (!ctx->skip_length) {
		snprintf(buf, sizeof(buf), "HTML Skip Length          :   %22s", "UNLIMITED");
	}
        else {
		w = comma_snprintf(nbuf, sizeof(nbuf), "%ld", ctx->skip_length);
		snprintf(buf, sizeof(buf), "HTML Skip Length          :   %22s", w);
	}
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
        if (!ctx->condensed_max_length) {
		snprintf(buf, sizeof(buf), "HTML Extract Max Length   :   %22s", "UNLIMITED");
	}
        else {
		w = comma_snprintf(nbuf, sizeof(nbuf), "%ld", ctx->condensed_max_length);
		snprintf(buf, sizeof(buf), "HTML Extract Max Length   :   %22s", w);
	}
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "Show Skipped Content      :   %22s", ctx->show_skipped_requests ? "ON" : "OFF");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);
	snprintf(buf, sizeof(buf), "Wipe Database at Startup  :   %22s", ctx->db_init_startup ? "ON" : "OFF");
	write_portal_cleol(portal, (const char *)buf, row++, 2, BRITEWHITE | BGBLUE);

	write_portal_cleol(portal, (const char *)" ", row++, 2, BRITEWHITE | BGBLUE);

	if (mutex_sem) {
		sem_close(mutex_sem);
		mutex_sem = NULL;
	}

	if (stats_ptr) {
		munmap(stats_ptr, sizeof(GLOBAL));
		stats_ptr = NULL;
	}
	if (stats_shm > 0) {
		close(stats_shm);
		stats_shm = 0;
	}

	return 1;
}

void *mysql_routine(void *p)
{
   NP *np = (NP *)p;
   int portal = np ? np->portal : 0;
   LCTX *ctx = np ? np->ctx : NULL;
   int state;

   while (mysqlactive && p && np)
   {
      pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
      mysql_summary(portal, ctx);
      update_static_portal(portal);
      pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &state);
      sleep(1);
      if (!get_sleep_count(portal))
         clear_portal_focus(portal);
   }
   return NULL;
}

void *pstat_routine(void *p)
{
   NP *np = (NP *)p;
   int portal = np ? np->portal : 0;
   STATE *st = np ? np->state : NULL;
   PSTATE *pr = np ? np->pstate : NULL;
   LCTX *ctx = np ? np->ctx : NULL;
   int state;

   while (active && p && np)
   {
       pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
       display_leaf_summary(portal, st, pr, ctx, &np->list, SHORT_FORMAT);
       update_static_portal(portal);
       pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &state);
       sleep(1);
       if (!get_sleep_count(portal))
          clear_portal_focus(portal);
   }
   return NULL;
}

ULONG netmenuKeyboardHandler(NWSCREEN *screen, ULONG key, ULONG index)
{
    BYTE display_buffer[1024];

    switch (key)
    {
       case F1:
          snprintf((char *)display_buffer, sizeof(display_buffer),
                  "Go Read the IFCONFIG Manual Page");
          error_portal((const char *)display_buffer,
		      ((get_screen_lines() - 2) / 2));
          break;

       default:
	  break;
    }
    return 0;
}

ULONG netmenuFunction(NWSCREEN *screen, ULONG value, BYTE *option,
                      ULONG menu_index)
{
    int portal = 0;
    char display_buffer[1024];
    NP np;

    switch (value)
    {
       default:
          snprintf(display_buffer, sizeof(display_buffer),
		   "Interface [%s] Statistics", option);
          portal = make_portal(get_console_screen(),
		       (char *)display_buffer,
		       0,
		       3,
		       0,
		       get_screen_lines() - 2,
		       get_screen_cols() - 1,
		       1024,
		       BORDER_SINGLE,
		       YELLOW | BGBLUE,
		       YELLOW | BGBLUE,
		       BRITEWHITE | BGBLUE,
		       BRITEWHITE | BGBLUE,
		       NULL,
		       0,
		       NULL,
		       TRUE);
          if (!portal)
             return 0;

          snprintf((char *)display_buffer, sizeof(display_buffer),
                  "  F1-Help  F3-Return to Menu  [terminal:%s]",
                  get_term_name());
          write_screen_comment_line(get_console_screen(),
				    (const char *)display_buffer,
				    BLUE | BGWHITE);

          activate_static_portal(portal);
          update_static_portal(portal);

          networkactive = TRUE;
          memset(&np, 0, sizeof(NP));
          np.portal = portal;
          strncpy((char *)np.ifname, (const char *)option, IFNAMSIZ);
          pthread_create(&networkstat, NULL, network_routine, &np);

          enable_portal_focus(portal, 5);
          get_portal_resp(portal);

          networkactive = 0;
          pthread_cancel(networkstat);
          pthread_join(networkstat, NULL);

          snprintf((char *)display_buffer, sizeof(display_buffer),
		   "  F1-Help  F3-Exit  TAB-View Stats  "
		   "[terminal:%s]", get_term_name());
          write_screen_comment_line(get_console_screen(),
				    (const char *)display_buffer,
				    BLUE | BGWHITE);
          if (portal)
          {
             deactivate_static_portal(portal);
             free_portal(portal);
          }
          break;
    }
    return 0;
}

int build_network_menu(void)
{
    FILE *fp;
    char buf[1024];
    int err, netmenu, index = 1, skfd;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (skfd < 0)
       return skfd;

    fp = fopen("/proc/net/dev", "r");
    if (!fp)
    {
       close(skfd);
       return -1;
    }

    netmenu = make_menu(get_console_screen(),
		     "  Network Devices  ",
		     ((get_screen_lines() - 1) / 2),
		     ((get_screen_cols() - 1) / 2) -
                     ((strlen("  Network Devices  ") + 4) / 2),
		     7,
		     BORDER_DOUBLE,
		     YELLOW | BGBLUE,
		     YELLOW | BGBLUE,
		     BRITEWHITE | BGBLUE,
		     BRITEWHITE | BGBLUE,
                     netmenuFunction,
		     NULL,
		     netmenuKeyboardHandler,
		     TRUE,
		     0);

    if (!netmenu)
    {
       fclose(fp);
       close(skfd);
       return -1;
    }

    fgets(buf, sizeof buf, fp);	 // eat line
    fgets(buf, sizeof buf, fp);

    err = 0;
    while (fgets(buf, sizeof buf, fp))
    {
	char name[IFNAMSIZ+1];
	get_name(name, buf);
        add_item_to_menu(netmenu, name, index++);
    }
    fclose(fp);
    close(skfd);

    mask_portal(mainportal);

    err = activate_menu(netmenu);

    unmask_portal(mainportal);

    if (netmenu)
       free_menu(netmenu);

    return err;
}

#define CONFIG_NAME        "  Leaf Server Monitor for Linux"
#define COPYRIGHT_NOTICE1  "  Copyright (c) 1997-2020 Leaf Linux. All Rights Reserved."
#define COPYRIGHT_NOTICE2  "  "

ULONG menuFunction(NWSCREEN *screen, ULONG value, BYTE *option,
                   ULONG menu_index)
{
    int portal = 0;
    unsigned char display_buffer[1024];
    NP np;

    switch (value)
    {
       case 1:
          portal = make_portal(get_console_screen(),
		       "Server Summary",
		       0,
		       3,
		       0,
		       get_screen_lines() - 2,
		       get_screen_cols() - 1,
		       1024,
		       BORDER_SINGLE,
		       YELLOW | BGBLUE,
		       YELLOW | BGBLUE,
		       BRITEWHITE | BGBLUE,
		       BRITEWHITE | BGBLUE,
		       NULL,
		       0,
		       NULL,
		       TRUE);
          if (!portal)
             return 0;

          mask_portal(mainportal);

          snprintf((char *)display_buffer, sizeof(display_buffer),
                  "  F1-Help  F3-Return to Menu  [terminal:%s]",
                  get_term_name());
          write_screen_comment_line(get_console_screen(),
				    (const char *)display_buffer,
				    BLUE | BGWHITE);

          activate_static_portal(portal);
          update_static_portal(portal);

          memset(&np, 0, sizeof(NP));
	  np.portal = portal;	
          np.state = (STATE *)malloc(sizeof(STATE));
    	  if (np.state) 
  	     memset(np.state, 0, sizeof(STATE));
          np.pstate = (PSTATE *)malloc(sizeof(PSTATE));
          if (np.pstate) 
    	     memset(np.pstate, 0, sizeof(PSTATE));
          np.ctx = (LCTX *)malloc(sizeof(LCTX));
          if (np.ctx) 
 	     memset(np.ctx, 0, sizeof(LCTX));

          np.list.current = (struct user_net_device_stats *)malloc(sizeof(struct user_net_device_stats));
          if (np.list.current) 
  	     memset(np.list.current, 0, sizeof(struct user_net_device_stats));
          np.list.previous = (struct user_net_device_stats *)malloc(sizeof(struct user_net_device_stats));
          if (np.list.previous) 
	     memset(np.list.previous, 0, sizeof(struct user_net_device_stats));

          leafsumactive = TRUE;
          pthread_create(&netsumstat, NULL, leaf_summary_routine, &np);

          enable_portal_focus(portal, 5);
          get_portal_resp(portal);

          leafsumactive = 0;
          pthread_cancel(netsumstat);
          pthread_join(netsumstat, NULL);

          if (np.state) {
             free(np.state);
             np.state = NULL;
          }
          if (np.pstate) {
             free(np.pstate);
             np.pstate = NULL;
          }
          if (np.ctx) {
             free(np.ctx);
             np.ctx = NULL;
          }
          if (np.list.current) {
	     free(np.list.current);
	     np.list.current = NULL;
          }
          if (np.list.previous) {
	     free(np.list.previous);
 	     np.list.previous = NULL;
          }
          free_node_list(&np.list);

          snprintf((char *)display_buffer, sizeof(display_buffer),
		   "  F1-Help  F3-Exit  TAB-View Stats  "
		   "[terminal:%s]", get_term_name());
          write_screen_comment_line(get_console_screen(),
				    (const char *)display_buffer,
				    BLUE | BGWHITE);
          if (portal)
          {
             deactivate_static_portal(portal);
             free_portal(portal);
          }
          unmask_portal(mainportal);
          break;

       case 2:
          //build_network_menu();
          portal = make_portal(get_console_screen(),
		       "Network Summary",
		       0,
		       3,
		       0,
		       get_screen_lines() - 2,
		       get_screen_cols() - 1,
		       1024,
		       BORDER_SINGLE,
		       YELLOW | BGBLUE,
		       YELLOW | BGBLUE,
		       BRITEWHITE | BGBLUE,
		       BRITEWHITE | BGBLUE,
		       NULL,
		       0,
		       NULL,
		       TRUE);
          if (!portal)
             return 0;

          mask_portal(mainportal);

          snprintf((char *)display_buffer, sizeof(display_buffer),
                  "  F1-Help  F3-Return to Menu  [terminal:%s]",
                  get_term_name());
          write_screen_comment_line(get_console_screen(),
				    (const char *)display_buffer,
				    BLUE | BGWHITE);

          activate_static_portal(portal);
          update_static_portal(portal);

          netsumactive = TRUE;
          memset(&np, 0, sizeof(NP));
	  np.portal = portal;	

          np.list.current = (struct user_net_device_stats *)malloc(sizeof(struct user_net_device_stats));
          if (np.list.current) 
  	     memset(np.list.current, 0, sizeof(struct user_net_device_stats));
          np.list.previous = (struct user_net_device_stats *)malloc(sizeof(struct user_net_device_stats));
          if (np.list.previous) 
	     memset(np.list.previous, 0, sizeof(struct user_net_device_stats));

          pthread_create(&netsumstat, NULL, network_summary_routine, &np);

          enable_portal_focus(portal, 5);
          get_portal_resp(portal);

          netsumactive = 0;
          pthread_cancel(netsumstat);
          pthread_join(netsumstat, NULL);

          if (np.list.current) {
	     free(np.list.current);
	     np.list.current = NULL;
          }
          if (np.list.previous) {
	     free(np.list.previous);
 	     np.list.previous = NULL;
          }
          free_node_list(&np.list);

          snprintf((char *)display_buffer, sizeof(display_buffer),
		   "  F1-Help  F3-Exit  TAB-View Stats  "
		   "[terminal:%s]", get_term_name());
          write_screen_comment_line(get_console_screen(),
				    (const char *)display_buffer,
				    BLUE | BGWHITE);
          if (portal)
          {
             deactivate_static_portal(portal);
             free_portal(portal);
          }
          unmask_portal(mainportal);
          break;

       case 3:
          portal = make_portal(get_console_screen(),
		       "Disk Summary",
		       0,
		       3,
		       0,
		       get_screen_lines() - 2,
		       get_screen_cols() - 1,
		       1024,
		       BORDER_SINGLE,
		       YELLOW | BGBLUE,
		       YELLOW | BGBLUE,
		       BRITEWHITE | BGBLUE,
		       BRITEWHITE | BGBLUE,
		       NULL,
		       0,
		       NULL,
		       TRUE);
          if (!portal)
             return 0;

          mask_portal(mainportal);

          snprintf((char *)display_buffer, sizeof(display_buffer),
                  "  F1-Help  F3-Return to Menu  [terminal:%s]",
                  get_term_name());
          write_screen_comment_line(get_console_screen(),
				    (const char *)display_buffer,
				    BLUE | BGWHITE);

          activate_static_portal(portal);
          update_static_portal(portal);

          leafdiskactive = TRUE;
	  memset(&np, 0, sizeof(NP));
	  np.portal = portal;	
          np.pstate = (PSTATE *)malloc(sizeof(PSTATE));
          if (np.pstate) 
	     memset(np.pstate, 0, sizeof(PSTATE));

          pthread_create(&diskstat, NULL, leaf_disk_routine, &np);

          enable_portal_focus(portal, 5);
          get_portal_resp(portal);

          leafdiskactive = 0;
          pthread_cancel(diskstat);
          pthread_join(diskstat, NULL);

          if (np.pstate) {
             free(np.pstate);
             np.pstate = NULL;
          }

          snprintf((char *)display_buffer, sizeof(display_buffer),
		   "  F1-Help  F3-Exit  TAB-View Stats  "
		   "[terminal:%s]", get_term_name());
          write_screen_comment_line(get_console_screen(),
				    (const char *)display_buffer,
				    BLUE | BGWHITE);
          if (portal)
          {
             deactivate_static_portal(portal);
             free_portal(portal);
          }
          unmask_portal(mainportal);
          break;

       case 4:
          portal = make_portal(get_console_screen(),
		       "C-ICAP Summary",
		       0,
		       3,
		       0,
		       get_screen_lines() - 2,
		       get_screen_cols() - 1,
		       1024,
		       BORDER_SINGLE,
		       YELLOW | BGBLUE,
		       YELLOW | BGBLUE,
		       BRITEWHITE | BGBLUE,
		       BRITEWHITE | BGBLUE,
		       NULL,
		       0,
		       NULL,
		       TRUE);
          if (!portal)
             return 0;

          mask_portal(mainportal);

          snprintf((char *)display_buffer, sizeof(display_buffer),
                  "  F1-Help  F3-Return to Menu  [terminal:%s]",
                  get_term_name());
          write_screen_comment_line(get_console_screen(),
				    (const char *)display_buffer,
				    BLUE | BGWHITE);

          activate_static_portal(portal);
          update_static_portal(portal);

          cicapactive = TRUE;
    	  memset(&np, 0, sizeof(NP));
	  np.portal = portal;	

          pthread_create(&cicapstat, NULL, cicap_routine, &np);

          enable_portal_focus(portal, 5);
          get_portal_resp(portal);

          cicapactive = 0;
          pthread_cancel(cicapstat);
          pthread_join(cicapstat, NULL);

          snprintf((char *)display_buffer, sizeof(display_buffer),
		   "  F1-Help  F3-Exit  TAB-View Stats  "
		   "[terminal:%s]", get_term_name());
          write_screen_comment_line(get_console_screen(),
				    (const char *)display_buffer,
				    BLUE | BGWHITE);
          if (portal)
          {
             deactivate_static_portal(portal);
             free_portal(portal);
          }
          unmask_portal(mainportal);
          break;

       case 5:
          portal = make_portal(get_console_screen(),
		       "MYSQL Summary",
		       0,
		       3,
		       0,
		       get_screen_lines() - 2,
		       get_screen_cols() - 1,
		       1024,
		       BORDER_SINGLE,
		       YELLOW | BGBLUE,
		       YELLOW | BGBLUE,
		       BRITEWHITE | BGBLUE,
		       BRITEWHITE | BGBLUE,
		       NULL,
		       0,
		       NULL,
		       TRUE);
          if (!portal)
             return 0;

          mask_portal(mainportal);

          snprintf((char *)display_buffer, sizeof(display_buffer),
                  "  F1-Help  F3-Return to Menu  [terminal:%s]",
                  get_term_name());
          write_screen_comment_line(get_console_screen(),
				    (const char *)display_buffer,
				    BLUE | BGWHITE);

          activate_static_portal(portal);
          update_static_portal(portal);

          memset(&np, 0, sizeof(NP));
	  np.portal = portal;	
          np.state = (STATE *)malloc(sizeof(STATE));
    	  if (np.state) 
  	     memset(np.state, 0, sizeof(STATE));
          np.pstate = (PSTATE *)malloc(sizeof(PSTATE));
          if (np.pstate) 
    	     memset(np.pstate, 0, sizeof(PSTATE));
          np.ctx = (LCTX *)malloc(sizeof(LCTX));
          if (np.ctx) 
 	     memset(np.ctx, 0, sizeof(LCTX));

          np.list.current = (struct user_net_device_stats *)malloc(sizeof(struct user_net_device_stats));
          if (np.list.current) 
  	     memset(np.list.current, 0, sizeof(struct user_net_device_stats));
          np.list.previous = (struct user_net_device_stats *)malloc(sizeof(struct user_net_device_stats));
          if (np.list.previous) 
	     memset(np.list.previous, 0, sizeof(struct user_net_device_stats));

          mysqlactive = TRUE;
          pthread_create(&mysqlstat, NULL, mysql_routine, &np);

          enable_portal_focus(portal, 5);
          get_portal_resp(portal);

          mysqlactive = 0;
          pthread_cancel(mysqlstat);
          pthread_join(mysqlstat, NULL);

          if (np.state) {
             free(np.state);
             np.state = NULL;
          }
          if (np.pstate) {
             free(np.pstate);
             np.pstate = NULL;
          }
          if (np.ctx) {
             free(np.ctx);
             np.ctx = NULL;
          }
          if (np.list.current) {
	     free(np.list.current);
	     np.list.current = NULL;
          }
          if (np.list.previous) {
	     free(np.list.previous);
 	     np.list.previous = NULL;
          }
          free_node_list(&np.list);

          snprintf((char *)display_buffer, sizeof(display_buffer),
		   "  F1-Help  F3-Exit  TAB-View Stats  "
		   "[terminal:%s]", get_term_name());
          write_screen_comment_line(get_console_screen(),
				    (const char *)display_buffer,
				    BLUE | BGWHITE);
          if (portal)
          {
             deactivate_static_portal(portal);
             free_portal(portal);
          }
          unmask_portal(mainportal);
          break;

    }
    return 0;

}

ULONG menuKeyboardHandler(NWSCREEN *screen, ULONG key, ULONG index)
{
    BYTE display_buffer[1024];

    switch (key)
    {
       case F1:
          mask_portal(mainportal);
          snprintf((char *)display_buffer, sizeof(display_buffer),
		   "Help for Leaf Monitor Program.");
          error_portal((const char *)display_buffer,
		      ((get_screen_lines() - 2) / 2));
          unmask_portal(mainportal);
          break;

       case TAB:
	  if (mainportal)
	  {
	     snprintf((char *)display_buffer, sizeof(display_buffer),
		      "  F1-Help  F3-Return to Menu  "
		      "[terminal:%s]", get_term_name());
	     write_screen_comment_line(get_console_screen(),
				       (const char *)display_buffer,
				       BLUE | BGWHITE);

             enable_portal_focus(mainportal, -1);
	     get_portal_resp(mainportal);

             snprintf((char *)display_buffer, sizeof(display_buffer),
                      "  F1-Help  F3-Exit  TAB-Switch to Stats "
		      " [terminal:%s]", get_term_name());
             write_screen_comment_line(get_console_screen(),
				       (const char *)display_buffer,
				       BLUE | BGWHITE);
	  }
	  break;

       default:
	  break;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    register int i;
    register ULONG retCode = 0, ssi;
    BYTE display_buffer[1024];
    register int plines, mlines, mlen = 0;
    struct utsname utsbuf;
    NP np;

    for (i=0; i < argc; i++)
    {
       if (!strcasecmp(argv[i], "-h"))
       {
          printf("USAGE:  leafmon (text|mono|unicode)\n");
          printf("        text           - disable box line drawing\n");
          printf("        mono           - disable color mode\n");
          printf("        unicode        - enable unicode support\n");
          printf("        leafmon -h     - this help screen\n");
          printf("        leafmon -help  - this help screen\n");
          exit(0);
       }

       if (!strcasecmp(argv[i], "-help"))
       {
          printf("USAGE:  leafmon (text|mono|unicode)\n");
          printf("        text           - disable box line drawing\n");
          printf("        mono           - disable color mode\n");
          printf("        unicode        - enable unicode support\n");
          printf("        leafmon -h     - this help screen\n");
          printf("        leafmon -help  - this help screen\n");
          exit(0);
       }

       if (!strcasecmp(argv[i], "text"))
          set_text_mode(1);

       if (!strcasecmp(argv[i], "mono"))
          set_mono_mode(1);

       if (!strcasecmp(argv[i], "unicode"))
          set_unicode_mode(1);
    }

    if (init_cworthy())
       return 0;

    // set ssi in seconds
    ssi = set_screensaver_interval(3 * 60);

    for (i=0; i < (get_screen_lines() - 1); i++)
    {
       put_char_cleol(get_console_screen(), 176 | A_ALTCHARSET, i, CYAN | BGBLUE);
    }

    unsigned long header_attr = BLUE | BGCYAN;
#if LINUX_UTIL
    if (is_xterm())
       header_attr = BRITEWHITE | BGCYAN;
    if (mono_mode || !has_color)
       header_attr = BLUE | BGWHITE;
#endif
    snprintf((char *)display_buffer, sizeof(display_buffer), CONFIG_NAME);
    put_string_cleol(get_console_screen(), (const char *)display_buffer, NULL, 0, header_attr);

    snprintf((char *)display_buffer, sizeof(display_buffer), COPYRIGHT_NOTICE1);
    put_string_cleol(get_console_screen(), (const char *)display_buffer, NULL, 1, header_attr);

    if (!uname(&utsbuf)) {
       snprintf((char *)display_buffer, sizeof(display_buffer),
		"  %s %s %s (%s) [%s]", utsbuf.sysname, utsbuf.release,
		utsbuf.version, utsbuf.machine,
		utsbuf.nodename);
    } else {
       snprintf((char *)display_buffer, sizeof(display_buffer),
		COPYRIGHT_NOTICE2);
    }
    put_string_cleol(get_console_screen(), (const char *)display_buffer, NULL, 2, header_attr);

    snprintf((char *)display_buffer, sizeof(display_buffer),
             "  F1-Help  F3-Exit  TAB-View Stats "
	     " [terminal:%s]", get_term_name());
    write_screen_comment_line(get_console_screen(),
			      (const char *)display_buffer,
			      BLUE | BGWHITE);

   // adjust portal and menu sizes based on screen size
    plines = get_screen_lines() >= 34
	     ? get_screen_lines() - 13
	     : get_screen_lines() - 9;
    mlines = get_screen_lines() >= 34
	     ? get_screen_lines() - 12
	     : get_screen_lines() - 8;
    mlen   = get_screen_lines() >= 34 ? 5 : 3;
    if (mlen) {};

    mainportal = make_portal(get_console_screen(),
		       "Leaf Server Monitor",
		       0,
		       3,
		       0,
		       plines,
		       get_screen_cols() - 1,
		       1024,
		       BORDER_SINGLE,
		       YELLOW | BGBLUE,
		       YELLOW | BGBLUE,
		       BRITEWHITE | BGBLUE,
		       BRITEWHITE | BGBLUE,
		       NULL,
		       0,
		       NULL,
		       TRUE);
    if (!mainportal)
       goto ErrorExit;

    activate_static_portal(mainportal);
    update_static_portal(mainportal);

    menu = make_menu(get_console_screen(),
		     "  Available Options  ",
		     mlines,
		     ((get_screen_cols() - 1) / 2) -
                     ((strlen("  Available Options  ") + 4) / 2),
		     mlen,
		     BORDER_DOUBLE,
		     YELLOW | BGBLUE,
		     YELLOW | BGBLUE,
		     BRITEWHITE | BGBLUE,
		     BRITEWHITE | BGBLUE,
		     menuFunction,
		     warn_func,
		     menuKeyboardHandler,
		     TRUE,
		     0);

    if (!menu)
	  goto ErrorExit;

    add_item_to_menu(menu, "System Summary", 1);
    add_item_to_menu(menu, "Network Summary", 2);
    add_item_to_menu(menu, "Disk Summary", 3);
    add_item_to_menu(menu, "ICAP Summary", 4);
    add_item_to_menu(menu, "MYSQL Summary", 5);

    memset(&np, 0, sizeof(NP));
    np.portal = mainportal;	
    np.state = (STATE *)malloc(sizeof(STATE));
    if (np.state) 
	memset(np.state, 0, sizeof(STATE));
    np.pstate = (PSTATE *)malloc(sizeof(PSTATE));
    if (np.pstate) 
	memset(np.pstate, 0, sizeof(PSTATE));
    np.ctx = (LCTX *)malloc(sizeof(LCTX));
    if (np.ctx) 
	memset(np.ctx, 0, sizeof(LCTX));

    np.list.current = (struct user_net_device_stats *)malloc(sizeof(struct user_net_device_stats));
    if (np.list.current) 
	memset(np.list.current, 0, sizeof(struct user_net_device_stats));
    np.list.previous = (struct user_net_device_stats *)malloc(sizeof(struct user_net_device_stats));
    if (np.list.previous) 
	memset(np.list.previous, 0, sizeof(struct user_net_device_stats));

    active = TRUE;
    pthread_create(&pstat, NULL, pstat_routine, &np);
    retCode = activate_menu(menu);
    active = 0;
    pthread_cancel(pstat);
    pthread_join(pstat, NULL);

    if (np.state) {
       free(np.state);
       np.state = NULL;
    }
    if (np.pstate) {
       free(np.pstate);
       np.pstate = NULL;
    }
    if (np.ctx) {
       free(np.ctx);
       np.ctx = NULL;
    }
    if (np.list.current) {
	free(np.list.current);
	np.list.current = NULL;
    }
    if (np.list.previous) {
	free(np.list.previous);
	np.list.previous = NULL;
    }
    free_node_list(&np.list);

ErrorExit:;
    snprintf((char *)display_buffer, sizeof(display_buffer), " Exiting ... ");
    write_screen_comment_line(get_console_screen(),
			      (const char *)display_buffer, BLUE | BGWHITE);


    if (mainportal)
    {
       deactivate_static_portal(mainportal);
       free_portal(mainportal);
    }

    if (menu)
       free_menu(menu);

    set_screensaver_interval(ssi);
    release_cworthy();
    return retCode;
}

